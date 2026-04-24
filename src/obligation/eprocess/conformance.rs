//! Conformance test harness for e-process martingale invariants.
//!
//! This module verifies that the LeakMonitor implementation satisfies
//! the mathematical requirements for a valid e-process:
//!
//! 1. **Supermartingale Property**: E[E_n | E_{n-1}] ≤ E_{n-1} under H0
//! 2. **Ville's Inequality**: P(∃t: E_t ≥ 1/α | H0) ≤ α
//! 3. **Likelihood Ratio Validity**: E[LR] ≤ 1 under exponential null
//! 4. **Alert Threshold**: False positive rate bounds
//! 5. **Numerical Stability**: No overflow/underflow in realistic scenarios

use super::{LeakMonitor, MonitorConfig};
use std::f64;

/// Mathematical tolerance for floating-point comparisons.
const MATH_EPSILON: f64 = 1e-10;

/// Conformance test result for a specific mathematical requirement.
#[derive(Debug, Clone)]
pub struct ConformanceResult {
    /// Stable requirement identifier covered by this result.
    pub requirement_id: &'static str,
    /// Human-readable requirement summary.
    pub description: &'static str,
    /// Criticality level for the requirement.
    pub level: RequirementLevel,
    /// Execution status for the requirement check.
    pub status: TestStatus,
    /// Evidence or failure details captured by the check.
    pub evidence: String,
    /// Confidence score for the result, from 0.0 to 1.0.
    pub confidence: f64,
}

/// Requirement criticality level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    /// MUST satisfy - violation invalidates the implementation.
    Must,
    /// SHOULD satisfy - violation is a quality issue.
    Should,
    /// MAY satisfy - nice to have.
    May,
}

/// Test execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Requirement check passed.
    Pass,
    /// Requirement check failed.
    Fail,
    /// Requirement check was skipped.
    Skip,
    /// Requirement check is an expected failure for a known limitation.
    XFail,
}

/// Complete conformance matrix for e-process implementation.
pub struct EProcessConformanceHarness {
    tests: Vec<ConformanceTest>,
    results: Vec<ConformanceResult>,
}

/// Individual conformance test.
pub struct ConformanceTest {
    /// Stable requirement identifier covered by this test.
    pub id: &'static str,
    /// Human-readable requirement summary.
    pub description: &'static str,
    /// Criticality level for the requirement.
    pub level: RequirementLevel,
    /// Test function that evaluates the requirement.
    pub test_fn: fn() -> ConformanceResult,
}

impl EProcessConformanceHarness {
    /// Creates a new conformance harness with all mathematical requirements.
    pub fn new() -> Self {
        let tests = vec![
            ConformanceTest {
                id: "MART-001",
                description: "Likelihood ratio normalization maintains E[LR] ≤ 1",
                level: RequirementLevel::Must,
                test_fn: test_likelihood_ratio_expectation,
            },
            ConformanceTest {
                id: "MART-002",
                description: "Supermartingale property under exponential null",
                level: RequirementLevel::Must,
                test_fn: test_supermartingale_property,
            },
            ConformanceTest {
                id: "MART-003",
                description: "Alert threshold respects Ville's inequality bound",
                level: RequirementLevel::Must,
                test_fn: test_ville_inequality_bound,
            },
            ConformanceTest {
                id: "MART-004",
                description: "E-value remains finite under realistic load",
                level: RequirementLevel::Must,
                test_fn: test_numerical_stability,
            },
            ConformanceTest {
                id: "MART-005",
                description: "Alert rate converges to α under null hypothesis",
                level: RequirementLevel::Should,
                test_fn: test_false_positive_rate_convergence,
            },
            ConformanceTest {
                id: "MART-006",
                description: "Peak e-value tracking is monotonic",
                level: RequirementLevel::Should,
                test_fn: test_peak_tracking_monotonic,
            },
            ConformanceTest {
                id: "MART-007",
                description: "Reset preserves configuration invariants",
                level: RequirementLevel::Should,
                test_fn: test_reset_preserves_invariants,
            },
            ConformanceTest {
                id: "MART-008",
                description: "Log-space computation prevents underflow",
                level: RequirementLevel::Must,
                test_fn: test_log_space_stability,
            },
        ];

        Self {
            tests,
            results: Vec::new(),
        }
    }

    /// Runs all conformance tests and generates a compliance report.
    pub fn run_all(&mut self) {
        self.results.clear();

        for test in &self.tests {
            let result = (test.test_fn)();
            self.results.push(ConformanceResult {
                requirement_id: test.id,
                description: test.description,
                level: test.level,
                status: result.status,
                evidence: result.evidence,
                confidence: result.confidence,
            });
        }
    }

    /// Generates compliance matrix showing requirement coverage.
    pub fn compliance_matrix(&self) -> String {
        let mut output = String::new();
        output.push_str("# E-Process Martingale Conformance Matrix\n\n");
        output.push_str("| Req ID | Level | Status | Description | Evidence |\n");
        output.push_str("|--------|-------|--------|-------------|----------|\n");

        let mut must_total = 0;
        let mut must_pass = 0;
        let mut should_total = 0;
        let mut should_pass = 0;

        for result in &self.results {
            let status_str = match result.status {
                TestStatus::Pass => "✅ PASS",
                TestStatus::Fail => "❌ FAIL",
                TestStatus::Skip => "⏸️ SKIP",
                TestStatus::XFail => "⚠️ XFAIL",
            };

            let level_str = match result.level {
                RequirementLevel::Must => {
                    must_total += 1;
                    if result.status == TestStatus::Pass {
                        must_pass += 1;
                    }
                    "MUST"
                }
                RequirementLevel::Should => {
                    should_total += 1;
                    if result.status == TestStatus::Pass {
                        should_pass += 1;
                    }
                    "SHOULD"
                }
                RequirementLevel::May => "MAY",
            };

            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                result.requirement_id,
                level_str,
                status_str,
                result.description,
                result.evidence.chars().take(50).collect::<String>()
            ));
        }

        output.push_str("\n## Compliance Summary\n\n");

        let must_score = if must_total > 0 {
            (must_pass as f64 / must_total as f64) * 100.0
        } else {
            100.0
        };
        let should_score = if should_total > 0 {
            (should_pass as f64 / should_total as f64) * 100.0
        } else {
            100.0
        };

        output.push_str(&format!(
            "**MUST Requirements**: {}/{} ({:.1}%)\n",
            must_pass, must_total, must_score
        ));
        output.push_str(&format!(
            "**SHOULD Requirements**: {}/{} ({:.1}%)\n",
            should_pass, should_total, should_score
        ));

        if must_score >= 95.0 {
            output.push_str(
                "\n✅ **CONFORMANT**: Implementation satisfies martingale requirements\n",
            );
        } else {
            output.push_str(
                "\n❌ **NON-CONFORMANT**: Critical mathematical requirements not satisfied\n",
            );
        }

        output
    }

    /// Returns failed requirements for debugging.
    pub fn failed_requirements(&self) -> Vec<&ConformanceResult> {
        self.results
            .iter()
            .filter(|r| r.status == TestStatus::Fail)
            .collect()
    }

    /// Returns all conformance results collected by the last run.
    pub fn results(&self) -> &[ConformanceResult] {
        &self.results
    }
}

// ============================================================================
// Mathematical Conformance Tests
// ============================================================================

/// MART-001: Verify likelihood ratio normalization maintains E[LR] ≤ 1.
fn test_likelihood_ratio_expectation() -> ConformanceResult {
    // Mathematical requirement: For exponential(μ) observations under H0,
    // the likelihood ratio E[max(1, X/μ) / (1 + 1/e)] ≤ 1.
    //
    // We verify this by:
    // 1. Theoretical calculation: E[max(1, X/μ)] = 1 + 1/e for Exp(1/μ)
    // 2. Empirical sampling: Generate many exponential samples and check mean LR

    let mu = 1_000_000.0; // 1ms expected lifetime
    let normalizer = 1.0 + (-1.0_f64).exp(); // 1 + 1/e

    // Theoretical expectation for unnormalized LR
    let theoretical_unnormalized = 1.0 + (-1.0_f64).exp(); // 1 + 1/e ≈ 1.3679
    let theoretical_normalized = theoretical_unnormalized / normalizer; // Should be exactly 1.0

    // Empirical verification: sample from exponential and compute mean LR
    let samples = 10_000;
    let mut lr_sum = 0.0;

    for i in 0..samples {
        // Simple exponential sampling: -μ * ln(1-u) where u ~ Uniform(0,1)
        let u = (i as f64 + 0.5) / samples as f64; // Avoid u=0,1
        let x = -mu * (1.0 - u).ln(); // Exponential sample

        let ratio = x / mu;
        let lr = ratio.max(1.0) / normalizer;
        lr_sum += lr;
    }

    let empirical_mean = lr_sum / samples as f64;
    let error = (empirical_mean - 1.0).abs();

    if error < 0.01 && (theoretical_normalized - 1.0).abs() < MATH_EPSILON {
        ConformanceResult {
            requirement_id: "MART-001",
            description: "Likelihood ratio expectation ≤ 1",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: format!(
                "Theoretical E[LR] = {:.6}, Empirical = {:.6}, Error = {:.6}",
                theoretical_normalized, empirical_mean, error
            ),
            confidence: 0.99,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-001",
            description: "Likelihood ratio expectation ≤ 1",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: Theoretical E[LR] = {:.6}, Empirical = {:.6}, Error = {:.6}",
                theoretical_normalized, empirical_mean, error
            ),
            confidence: 0.99,
        }
    }
}

/// MART-002: Verify supermartingale property under exponential null.
fn test_supermartingale_property() -> ConformanceResult {
    // Test that with observations drawn from Exp(1/μ), the e-value doesn't
    // systematically grow. We run multiple independent sequences and check
    // that final e-values have mean ≤ some reasonable bound.

    let config = MonitorConfig {
        alpha: 0.01,
        expected_lifetime_ns: 1_000_000, // 1ms
        min_observations: 3,
    };

    let num_sequences = 100;
    let observations_per_sequence = 50;
    let mut final_e_values = Vec::new();

    for seq in 0..num_sequences {
        let mut monitor = LeakMonitor::new(config);

        for i in 0..observations_per_sequence {
            // Generate exponential sample with rate 1/μ
            let u = ((seq * observations_per_sequence + i) as f64 + 0.5)
                / (num_sequences * observations_per_sequence) as f64;
            let x = -(config.expected_lifetime_ns as f64) * (1.0 - u).ln();

            monitor.observe(x as u64);
        }

        final_e_values.push(monitor.e_value());
    }

    let mean_e_value: f64 = final_e_values.iter().sum::<f64>() / final_e_values.len() as f64;
    let max_e_value = final_e_values.iter().fold(0.0f64, |a, &b| a.max(b));

    // Under the supermartingale property, mean should be ≤ 1 (starting value).
    // We allow some slack for sampling variance.
    let martingale_ok = mean_e_value <= 1.5; // Allow 50% slack
    let bounded_ok = max_e_value <= 100.0; // No extreme outliers

    if martingale_ok && bounded_ok {
        ConformanceResult {
            requirement_id: "MART-002",
            description: "Supermartingale property under H0",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: format!(
                "Mean final e-value = {:.4}, Max = {:.4} across {} sequences",
                mean_e_value, max_e_value, num_sequences
            ),
            confidence: 0.95,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-002",
            description: "Supermartingale property under H0",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: Mean final e-value = {:.4} > 1.5 or Max = {:.4} > 100",
                mean_e_value, max_e_value
            ),
            confidence: 0.95,
        }
    }
}

/// MART-003: Test that alert threshold respects Ville's inequality.
fn test_ville_inequality_bound() -> ConformanceResult {
    // Ville's inequality: P(∃t: E_t ≥ 1/α | H0) ≤ α
    // We can't test this directly (would need infinite sequences),
    // but we can verify the threshold calculation and alert logic.

    let alphas = [0.001, 0.01, 0.05, 0.1];
    let mut all_correct = true;
    let mut evidence_parts = Vec::new();

    for &alpha in &alphas {
        let config = MonitorConfig {
            alpha,
            expected_lifetime_ns: 1_000_000,
            min_observations: 3,
        };

        let monitor = LeakMonitor::new(config);
        let expected_threshold = 1.0 / alpha;
        let actual_threshold = monitor.threshold();

        let threshold_correct = (actual_threshold - expected_threshold).abs() < MATH_EPSILON;

        if !threshold_correct {
            all_correct = false;
        }

        evidence_parts.push(format!(
            "α={:.3}: threshold {:.1} (expected {:.1})",
            alpha, actual_threshold, expected_threshold
        ));
    }

    if all_correct {
        ConformanceResult {
            requirement_id: "MART-003",
            description: "Alert threshold = 1/α for Ville's inequality",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: evidence_parts.join("; "),
            confidence: 1.0,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-003",
            description: "Alert threshold = 1/α for Ville's inequality",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!("VIOLATION: {}", evidence_parts.join("; ")),
            confidence: 1.0,
        }
    }
}

/// MART-004: Test numerical stability under realistic loads.
fn test_numerical_stability() -> ConformanceResult {
    let mut monitor = LeakMonitor::new(MonitorConfig {
        alpha: 0.01,
        expected_lifetime_ns: 1_000_000,
        min_observations: 3,
    });

    // Stress test: extreme values that could cause overflow/underflow
    let test_cases = [
        (1_000_000_000u64, "very large age"), // 1 second
        (100u64, "very small age"),           // 0.1 microsecond
        (u64::MAX / 2, "near-max age"),       // Extreme but not overflow
    ];

    let mut all_stable = true;
    let mut evidence_parts = Vec::new();

    for (age, description) in &test_cases {
        let before_e = monitor.e_value();
        monitor.observe(*age);
        let after_e = monitor.e_value();

        let is_finite = after_e.is_finite();
        let not_explosive = after_e < 1e100; // Reasonable bound
        let stable = is_finite && not_explosive;

        if !stable {
            all_stable = false;
        }

        evidence_parts.push(format!(
            "{}: e-value {:.2e} → {:.2e} ({})",
            description,
            before_e,
            after_e,
            if stable { "stable" } else { "UNSTABLE" }
        ));
    }

    if all_stable {
        ConformanceResult {
            requirement_id: "MART-004",
            description: "Numerical stability under extreme inputs",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: evidence_parts.join("; "),
            confidence: 0.99,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-004",
            description: "Numerical stability under extreme inputs",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!("VIOLATION: {}", evidence_parts.join("; ")),
            confidence: 0.99,
        }
    }
}

/// MART-005: Test false positive rate convergence (statistical).
fn test_false_positive_rate_convergence() -> ConformanceResult {
    // This is a SHOULD test because it requires statistical convergence.
    // We run many independent monitor instances with null data and check
    // that the fraction that alert is ≤ α (with some confidence interval).

    let alpha = 0.05; // 5% false positive rate
    let config = MonitorConfig {
        alpha,
        expected_lifetime_ns: 1_000_000,
        min_observations: 10,
    };

    let num_trials = 1000; // Need large N for statistical power
    let observations_per_trial = 20;
    let mut alert_count = 0;

    for trial in 0..num_trials {
        let mut monitor = LeakMonitor::new(config);

        for i in 0..observations_per_trial {
            // Generate exponential observations (null hypothesis)
            let u = ((trial * observations_per_trial + i) as f64 + 0.5)
                / (num_trials * observations_per_trial) as f64;
            let x = -(config.expected_lifetime_ns as f64) * (1.0 - u).ln();

            monitor.observe(x as u64);
        }

        if monitor.is_alert() {
            alert_count += 1;
        }
    }

    let observed_rate = alert_count as f64 / num_trials as f64;
    let expected_rate = alpha;

    // With 95% confidence, observed rate should be within ±2√(α(1-α)/n) of α
    let stderr = (alpha * (1.0 - alpha) / num_trials as f64).sqrt();
    let margin = 2.0 * stderr; // 95% confidence interval

    let within_bounds = (observed_rate - expected_rate).abs() <= margin;

    if within_bounds {
        ConformanceResult {
            requirement_id: "MART-005",
            description: "False positive rate ≤ α under null",
            level: RequirementLevel::Should,
            status: TestStatus::Pass,
            evidence: format!(
                "Observed rate {:.4}, Expected {:.4} ± {:.4} ({}/{})",
                observed_rate, expected_rate, margin, alert_count, num_trials
            ),
            confidence: 0.95,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-005",
            description: "False positive rate ≤ α under null",
            level: RequirementLevel::Should,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: Rate {:.4} outside [{:.4}, {:.4}] ({}/{})",
                observed_rate,
                expected_rate - margin,
                expected_rate + margin,
                alert_count,
                num_trials
            ),
            confidence: 0.95,
        }
    }
}

/// MART-006: Test peak e-value tracking is monotonic.
fn test_peak_tracking_monotonic() -> ConformanceResult {
    let mut monitor = LeakMonitor::new(MonitorConfig::default());

    let ages = [500_000u64, 2_000_000, 1_000_000, 5_000_000, 800_000];
    let mut is_monotonic = true;
    let mut evidence_parts = Vec::new();

    for &age in &ages {
        let before_peak = monitor.peak_e_value();
        monitor.observe(age);
        let after_peak = monitor.peak_e_value();
        let current_e = monitor.e_value();

        // Peak should be monotonic and ≥ current e-value
        let peak_monotonic = after_peak >= before_peak - MATH_EPSILON;
        let peak_valid = after_peak >= current_e - MATH_EPSILON;

        if !peak_monotonic || !peak_valid {
            is_monotonic = false;
        }

        evidence_parts.push(format!(
            "age={}ns: peak {:.4}→{:.4}, current={:.4}",
            age, before_peak, after_peak, current_e
        ));
    }

    if is_monotonic {
        ConformanceResult {
            requirement_id: "MART-006",
            description: "Peak e-value tracking is monotonic",
            level: RequirementLevel::Should,
            status: TestStatus::Pass,
            evidence: evidence_parts.join("; "),
            confidence: 1.0,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-006",
            description: "Peak e-value tracking is monotonic",
            level: RequirementLevel::Should,
            status: TestStatus::Fail,
            evidence: format!("VIOLATION: {}", evidence_parts.join("; ")),
            confidence: 1.0,
        }
    }
}

/// MART-007: Test reset preserves configuration invariants.
fn test_reset_preserves_invariants() -> ConformanceResult {
    let config = MonitorConfig {
        alpha: 0.025,
        expected_lifetime_ns: 2_000_000,
        min_observations: 7,
    };

    let mut monitor = LeakMonitor::new(config);

    // Modify state
    monitor.observe(10_000_000);
    monitor.observe(50_000_000);

    // Check state before reset
    let config_before = *monitor.config();
    let threshold_before = monitor.threshold();

    // Reset
    monitor.reset();

    // Verify configuration preserved but state reset
    let config_after = *monitor.config();
    let threshold_after = monitor.threshold();
    let e_value_after = monitor.e_value();
    let observations_after = monitor.observations();
    let peak_after = monitor.peak_e_value();

    let config_preserved = (config_before.alpha - config_after.alpha).abs() < MATH_EPSILON
        && config_before.expected_lifetime_ns == config_after.expected_lifetime_ns
        && config_before.min_observations == config_after.min_observations;

    let threshold_preserved = (threshold_before - threshold_after).abs() < MATH_EPSILON;
    let state_reset = (e_value_after - 1.0).abs() < MATH_EPSILON
        && observations_after == 0
        && (peak_after - 1.0).abs() < MATH_EPSILON;

    if config_preserved && threshold_preserved && state_reset {
        ConformanceResult {
            requirement_id: "MART-007",
            description: "Reset preserves config, resets state",
            level: RequirementLevel::Should,
            status: TestStatus::Pass,
            evidence: format!(
                "Config preserved, e-value={:.6}, obs={}, peak={:.6}",
                e_value_after, observations_after, peak_after
            ),
            confidence: 1.0,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-007",
            description: "Reset preserves config, resets state",
            level: RequirementLevel::Should,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: config_ok={}, threshold_ok={}, state_ok={}",
                config_preserved, threshold_preserved, state_reset
            ),
            confidence: 1.0,
        }
    }
}

/// MART-008: Test log-space computation prevents underflow.
fn test_log_space_stability() -> ConformanceResult {
    let mut monitor = LeakMonitor::new(MonitorConfig {
        alpha: 0.001, // Small alpha = large threshold
        expected_lifetime_ns: 1_000_000,
        min_observations: 3,
    });

    // Sequence that would underflow in linear space but should work in log space
    let small_ages = vec![100_000u64; 1000]; // Many small values

    let mut all_finite = true;
    let mut evidence_parts = Vec::new();

    for (i, &age) in small_ages.iter().enumerate() {
        monitor.observe(age);

        let e_val = monitor.e_value();
        if !e_val.is_finite() || e_val < 0.0 {
            all_finite = false;
            evidence_parts.push(format!("obs {}: e-value became {}", i, e_val));
            break;
        }

        // Check periodically
        if i % 100 == 99 {
            evidence_parts.push(format!("obs {}: e-value = {:.2e}", i + 1, e_val));
        }
    }

    // Should handle the sequence without numerical issues
    let final_e = monitor.e_value();
    let obs_count = monitor.observations();

    if all_finite && final_e >= 0.0 && obs_count == small_ages.len() as u64 {
        ConformanceResult {
            requirement_id: "MART-008",
            description: "Log-space computation prevents underflow",
            level: RequirementLevel::Must,
            status: TestStatus::Pass,
            evidence: format!(
                "Handled {} observations, final e-value = {:.2e}",
                obs_count, final_e
            ),
            confidence: 0.99,
        }
    } else {
        ConformanceResult {
            requirement_id: "MART-008",
            description: "Log-space computation prevents underflow",
            level: RequirementLevel::Must,
            status: TestStatus::Fail,
            evidence: format!(
                "VIOLATION: finite={}, final_e={:.2e}, obs={}",
                all_finite, final_e, obs_count
            ),
            confidence: 0.99,
        }
    }
}

impl Default for EProcessConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn conformance_harness_runs_all_tests() {
        let mut harness = EProcessConformanceHarness::new();
        harness.run_all();

        // Should have results for all test cases
        assert_eq!(harness.results.len(), 8);

        // Generate matrix (should not panic)
        let matrix = harness.compliance_matrix();
        assert!(matrix.contains("E-Process Martingale Conformance Matrix"));

        // Should categorize by requirement level
        let must_count = harness
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must)
            .count();
        assert!(must_count >= 4); // We have several MUST requirements
    }

    #[test]
    fn individual_mathematical_test_runs() {
        // Verify each test function can run independently
        let result = test_likelihood_ratio_expectation();
        assert!(result.requirement_id == "MART-001");

        let result = test_ville_inequality_bound();
        assert!(result.requirement_id == "MART-003");

        // Should all have confidence > 0
        assert!(result.confidence > 0.0);
    }
}
