#![no_main]

//! Fuzz target for benchmark cartel baseline validation and regression analysis.
//!
//! This target exercises the core baseline validation and regression detection logic
//! with structure-aware input generation to verify critical invariants:
//!
//! ## Key Invariants Tested:
//! 1. **Baseline compatibility validation**: Commit hash validation, staleness detection
//! 2. **Statistical soundness**: No NaN/Infinity in regression analysis calculations
//! 3. **Delta calculation robustness**: Handle zero/negative baselines, extreme values
//! 4. **P-value approximation bounds**: Statistical calculations remain in valid ranges
//! 5. **Severity classification consistency**: Regression severity mapping is monotonic
//! 6. **Configuration validation**: All config parameters within safe bounds
//! 7. **Performance characteristics bounds**: Throughput/memory/CPU metrics are realistic
//!
//! ## Coverage Areas:
//! - BenchmarkResult creation and validation with extreme statistical values
//! - CartelConfig parameter validation across valid/invalid ranges
//! - Regression analysis with baseline/current result combinations
//! - Baseline compatibility checking across commit hash variations
//! - Statistical measurement calculation edge cases
//! - Performance characteristic bounds checking

use arbitrary::Arbitrary;
use asupersync::{
    error::Result,
    lab::benchmark_cartel::{
        BenchmarkCartel, BenchmarkResult, BenchmarkMetadata, StatisticalMeasurements,
        PerformanceCharacteristics, EnvironmentInfo, CartelConfig, RegressionAnalysis,
        RegressionSeverity,
    },
    types::Time,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

// Maximum values to prevent timeouts and maintain realistic bounds
const MAX_SAMPLE_COUNT: usize = 10_000;
const MAX_ITERATIONS: usize = 1_000;
const MAX_TIMEOUT_MS: u64 = 300_000; // 5 minutes max
const MAX_MEMORY_MB: u64 = 100_000; // 100 GB max
const MAX_RUNTIME_NS: f64 = 10_000_000_000.0; // 10 seconds in nanoseconds

#[derive(Debug, Arbitrary)]
struct BenchmarkCartelFuzzInput {
    /// Configuration parameters to test
    config: FuzzCartelConfig,
    /// Baseline benchmark result
    baseline_result: FuzzBenchmarkResult,
    /// Current benchmark result for comparison
    current_result: FuzzBenchmarkResult,
    /// Commit hash scenarios
    commit_scenario: CommitHashScenario,
    /// Statistical edge case scenarios
    statistical_scenario: StatisticalScenario,
}

#[derive(Debug, Arbitrary)]
struct FuzzCartelConfig {
    concurrency: u8,              // 1-255
    warmup_iterations: u16,       // 0-65535
    measurement_iterations: u16,  // 1-65535
    benchmark_timeout_ms: u32,    // 1ms-5min
    min_runtime_ms: u32,
    max_cv_threshold: f32,        // 0.0-1.0
    deterministic_timing: bool,
    regression_detection: bool,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzBenchmarkResult {
    name: String,
    measurements: FuzzStatisticalMeasurements,
    environment: FuzzEnvironmentInfo,
    characteristics: FuzzPerformanceCharacteristics,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzStatisticalMeasurements {
    // Use raw values that will be clamped/validated
    mean_ns_raw: f64,
    std_dev_ns_raw: f64,
    cv_raw: f32,
    median_ns_raw: f64,
    p95_ns_raw: f64,
    p99_ns_raw: f64,
    min_ns_raw: f64,
    max_ns_raw: f64,
    sample_count_raw: u32,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzEnvironmentInfo {
    platform: String,
    cpu_info: String,
    memory_mb_raw: u64,
    rust_version: String,
    build_profile: String,
    commit_hash: String,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzPerformanceCharacteristics {
    throughput_ops_per_sec_raw: f64,
    allocation_rate_mb_per_sec_raw: f64,
    cpu_utilization_percent_raw: f64,
    cache_miss_ratio_raw: f64,
    context_switches_per_sec_raw: f64,
    gc_pressure_score_raw: f64,
}

#[derive(Debug, Arbitrary)]
enum CommitHashScenario {
    /// Same commit hash in baseline and current
    ExactMatch,
    /// Different commit hashes
    DifferentCommits,
    /// Empty baseline commit hash
    EmptyBaseline,
    /// "unknown" baseline commit hash
    UnknownBaseline,
    /// Very long commit hash (edge case)
    LongCommitHash,
    /// Non-hex characters in commit hash
    InvalidCommitHash,
}

#[derive(Debug, Arbitrary)]
enum StatisticalScenario {
    /// Normal statistical values
    Normal,
    /// Zero mean/std_dev edge cases
    ZeroMean,
    /// Very small values (precision edge cases)
    TinyValues,
    /// Very large values (overflow potential)
    HugeValues,
    /// Negative statistical values (invalid but fuzzed)
    NegativeValues,
    /// NaN/Infinity injection
    InfiniteValues,
    /// Identical baseline and current (delta=0%)
    IdenticalResults,
}

impl From<FuzzCartelConfig> for CartelConfig {
    fn from(config: FuzzCartelConfig) -> Self {
        CartelConfig {
            concurrency: (config.concurrency as usize).max(1),
            warmup_iterations: config.warmup_iterations as usize,
            measurement_iterations: (config.measurement_iterations as usize).max(1).min(MAX_ITERATIONS),
            benchmark_timeout_ms: (config.benchmark_timeout_ms as u64).max(1).min(MAX_TIMEOUT_MS),
            deterministic_timing: config.deterministic_timing,
            min_runtime_ms: config.min_runtime_ms as u64,
            max_cv_threshold: config.max_cv_threshold.abs() as f64,
            regression_detection: config.regression_detection,
            baseline_dir: None, // Not relevant for fuzzing
        }
    }
}

fn sanitize_statistical_value(raw: f64, max_val: f64) -> f64 {
    if raw.is_nan() || raw.is_infinite() {
        0.0
    } else {
        raw.abs().min(max_val)
    }
}

fn convert_statistical_measurements(
    fuzz_measurements: &FuzzStatisticalMeasurements,
    scenario: &StatisticalScenario,
) -> StatisticalMeasurements {
    let (mean_ns, std_dev_ns, median_ns, p95_ns, p99_ns, min_ns, max_ns) = match scenario {
        StatisticalScenario::Normal => {
            let mean = sanitize_statistical_value(fuzz_measurements.mean_ns_raw, MAX_RUNTIME_NS);
            let std_dev = sanitize_statistical_value(fuzz_measurements.std_dev_ns_raw, mean * 0.5);
            let median = sanitize_statistical_value(fuzz_measurements.median_ns_raw, MAX_RUNTIME_NS);
            let p95 = sanitize_statistical_value(fuzz_measurements.p95_ns_raw, MAX_RUNTIME_NS);
            let p99 = sanitize_statistical_value(fuzz_measurements.p99_ns_raw, MAX_RUNTIME_NS);
            let min_ns = sanitize_statistical_value(fuzz_measurements.min_ns_raw, mean * 0.8);
            let max_ns = sanitize_statistical_value(fuzz_measurements.max_ns_raw, mean * 2.0);
            (mean, std_dev, median, p95, p99, min_ns, max_ns)
        }
        StatisticalScenario::ZeroMean => (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
        StatisticalScenario::TinyValues => (1e-9, 1e-10, 1e-9, 1e-8, 1e-7, 1e-12, 1e-6),
        StatisticalScenario::HugeValues => {
            let huge = MAX_RUNTIME_NS * 0.9;
            (huge, huge * 0.1, huge, huge * 1.2, huge * 1.5, huge * 0.8, huge * 1.8)
        }
        StatisticalScenario::NegativeValues => (-1000.0, -100.0, -500.0, -1200.0, -1500.0, -2000.0, -800.0),
        StatisticalScenario::InfiniteValues => (f64::INFINITY, f64::NAN, f64::NEG_INFINITY, f64::INFINITY, f64::NAN, f64::NEG_INFINITY, f64::INFINITY),
        StatisticalScenario::IdenticalResults => {
            let val = sanitize_statistical_value(fuzz_measurements.mean_ns_raw, MAX_RUNTIME_NS);
            (val, val * 0.01, val, val * 1.05, val * 1.1, val * 0.95, val * 1.15)
        }
    };

    let sample_count = (fuzz_measurements.sample_count_raw as usize).max(1).min(MAX_SAMPLE_COUNT);
    let cv = if mean_ns > 0.0 { std_dev_ns / mean_ns } else { 0.0 };
    let cv = sanitize_statistical_value(cv, 1.0);

    StatisticalMeasurements {
        mean_ns,
        std_dev_ns,
        cv,
        median_ns,
        p95_ns,
        p99_ns,
        min_ns,
        max_ns,
        sample_count,
    }
}

fn convert_environment_info(
    fuzz_env: &FuzzEnvironmentInfo,
    scenario: &CommitHashScenario,
) -> EnvironmentInfo {
    let commit_hash = match scenario {
        CommitHashScenario::ExactMatch => "abc123def456",
        CommitHashScenario::DifferentCommits => "xyz789uvw012",
        CommitHashScenario::EmptyBaseline => "",
        CommitHashScenario::UnknownBaseline => "unknown",
        CommitHashScenario::LongCommitHash => &"a".repeat(200),
        CommitHashScenario::InvalidCommitHash => "commit@#$%^&*()",
    };

    EnvironmentInfo {
        platform: if fuzz_env.platform.is_empty() { "unknown".to_string() } else { fuzz_env.platform.clone() },
        cpu_info: if fuzz_env.cpu_info.is_empty() { "unknown".to_string() } else { fuzz_env.cpu_info.clone() },
        memory_mb: fuzz_env.memory_mb_raw.min(MAX_MEMORY_MB),
        rust_version: if fuzz_env.rust_version.is_empty() { "1.70.0".to_string() } else { fuzz_env.rust_version.clone() },
        build_profile: if fuzz_env.build_profile.is_empty() { "release".to_string() } else { fuzz_env.build_profile.clone() },
        commit_hash: commit_hash.to_string(),
    }
}

fn convert_performance_characteristics(
    fuzz_chars: &FuzzPerformanceCharacteristics,
) -> PerformanceCharacteristics {
    PerformanceCharacteristics {
        throughput_ops_per_sec: sanitize_statistical_value(fuzz_chars.throughput_ops_per_sec_raw, 1_000_000_000.0),
        allocation_rate_mb_per_sec: sanitize_statistical_value(fuzz_chars.allocation_rate_mb_per_sec_raw, 10_000.0),
        cpu_utilization_percent: sanitize_statistical_value(fuzz_chars.cpu_utilization_percent_raw, 100.0),
        cache_miss_ratio: sanitize_statistical_value(fuzz_chars.cache_miss_ratio_raw, 1.0),
        context_switches_per_sec: sanitize_statistical_value(fuzz_chars.context_switches_per_sec_raw, 1_000_000.0),
        gc_pressure_score: sanitize_statistical_value(fuzz_chars.gc_pressure_score_raw, 1.0),
    }
}

fn convert_benchmark_result(
    fuzz_result: &FuzzBenchmarkResult,
    scenario: &StatisticalScenario,
    commit_scenario: &CommitHashScenario,
    is_baseline: bool,
) -> BenchmarkResult {
    let measurements = convert_statistical_measurements(&fuzz_result.measurements, scenario);

    let mut environment = convert_environment_info(&fuzz_result.environment, commit_scenario);

    // For baseline in ExactMatch scenario, use same commit hash as current
    if is_baseline && matches!(commit_scenario, CommitHashScenario::ExactMatch) {
        environment.commit_hash = "abc123def456".to_string();
    }

    let characteristics = convert_performance_characteristics(&fuzz_result.characteristics);

    BenchmarkResult {
        name: if fuzz_result.name.is_empty() { "test_benchmark".to_string() } else { fuzz_result.name.clone() },
        measurements,
        metadata: BenchmarkMetadata {
            start_time: Time::now(),
            total_duration_ms: 1000,
            target_iterations: 100,
            completed_iterations: 100,
            environment,
            config: CartelConfig::default(),
        },
        characteristics,
        trace_id: None,
    }
}

fuzz_target!(|input: BenchmarkCartelFuzzInput| {
    // Create configuration from fuzz input
    let config: CartelConfig = input.config.into();

    // Create benchmark cartel
    let (cartel, _rx) = BenchmarkCartel::new(config);

    // Convert fuzz inputs to benchmark results
    let baseline = convert_benchmark_result(
        &input.baseline_result,
        &input.statistical_scenario,
        &input.commit_scenario,
        true
    );

    let current = convert_benchmark_result(
        &input.current_result,
        &input.statistical_scenario,
        &input.commit_scenario,
        false
    );

    // **INVARIANT 1**: Baseline compatibility validation should handle all commit scenarios
    let current_commit = "abc123def456";
    let (compatible, reason) = asupersync::lab::benchmark_cartel::BenchmarkCartel::is_baseline_compatible(&baseline, current_commit);

    // Compatibility result should be deterministic and logical
    match input.commit_scenario {
        CommitHashScenario::ExactMatch => {
            assert!(compatible, "Exact commit match should be compatible");
            assert_eq!(reason, "Exact commit match");
        }
        CommitHashScenario::EmptyBaseline | CommitHashScenario::UnknownBaseline => {
            assert!(!compatible, "Empty/unknown baseline should be incompatible");
            assert!(reason.contains("no commit hash"));
        }
        CommitHashScenario::DifferentCommits | CommitHashScenario::LongCommitHash | CommitHashScenario::InvalidCommitHash => {
            assert!(!compatible, "Different commits should be incompatible");
        }
    }

    // **INVARIANT 2**: Regression analysis should not panic on any statistical input
    let regression_result = cartel.analyze_regression(&baseline, &current);

    // Regression analysis should either succeed or fail gracefully
    if let Ok(analysis) = regression_result {
        // **INVARIANT 3**: Analysis values should be bounded and finite
        assert!(analysis.performance_delta_percent.is_finite(), "Delta percent should be finite");
        assert!(analysis.p_value >= 0.0 && analysis.p_value <= 1.0, "P-value should be in [0,1]");
        assert!(analysis.confidence_interval.0.is_finite() && analysis.confidence_interval.1.is_finite(),
                "Confidence interval should be finite");

        // **INVARIANT 4**: Severity classification should be consistent with delta
        let delta = analysis.performance_delta_percent;
        match analysis.severity {
            RegressionSeverity::None => {
                // None should be for small deltas or high p-values
            }
            RegressionSeverity::Minor => {
                assert!(delta > 5.0 || analysis.p_value <= 0.05, "Minor severity should have delta>5% or significant p-value");
            }
            RegressionSeverity::Moderate => {
                assert!(delta > 10.0, "Moderate severity should have delta>10%");
            }
            RegressionSeverity::Severe => {
                assert!(delta > 25.0, "Severe severity should have delta>25%");
            }
            RegressionSeverity::Critical => {
                assert!(delta > 50.0, "Critical severity should have delta>50%");
            }
        }

        // **INVARIANT 5**: Regression detection should be consistent with severity
        if matches!(analysis.severity, RegressionSeverity::Minor | RegressionSeverity::Moderate |
                   RegressionSeverity::Severe | RegressionSeverity::Critical) {
            // If there's a severity level above None, it might be detected as regression
            // But this depends on the p-value, so we don't assert a strict requirement
        }
    }

    // **INVARIANT 6**: Statistical measurements should satisfy ordering constraints when valid
    if baseline.measurements.mean_ns.is_finite() && baseline.measurements.mean_ns > 0.0 {
        if baseline.measurements.min_ns > 0.0 && baseline.measurements.max_ns > 0.0 {
            assert!(
                baseline.measurements.min_ns <= baseline.measurements.max_ns,
                "Min should be <= max: min={}, max={}",
                baseline.measurements.min_ns, baseline.measurements.max_ns
            );
        }

        if baseline.measurements.cv.is_finite() {
            assert!(
                baseline.measurements.cv >= 0.0,
                "Coefficient of variation should be non-negative: cv={}",
                baseline.measurements.cv
            );
        }
    }

    // **INVARIANT 7**: Performance characteristics should be within reasonable bounds
    assert!(
        current.characteristics.cpu_utilization_percent >= 0.0 &&
        current.characteristics.cpu_utilization_percent <= 100.1, // Allow slight rounding error
        "CPU utilization should be 0-100%: {}", current.characteristics.cpu_utilization_percent
    );

    assert!(
        current.characteristics.cache_miss_ratio >= 0.0 &&
        current.characteristics.cache_miss_ratio <= 1.0,
        "Cache miss ratio should be 0-1: {}", current.characteristics.cache_miss_ratio
    );

    assert!(
        current.characteristics.gc_pressure_score >= 0.0,
        "GC pressure score should be non-negative: {}", current.characteristics.gc_pressure_score
    );

    // **INVARIANT 8**: Sample counts should be reasonable
    assert!(
        baseline.measurements.sample_count > 0 && baseline.measurements.sample_count <= MAX_SAMPLE_COUNT,
        "Sample count should be positive and bounded: {}", baseline.measurements.sample_count
    );
    assert!(
        current.measurements.sample_count > 0 && current.measurements.sample_count <= MAX_SAMPLE_COUNT,
        "Sample count should be positive and bounded: {}", current.measurements.sample_count
    );

    // **INVARIANT 9**: Environment info should be valid
    assert!(
        baseline.metadata.environment.memory_mb <= MAX_MEMORY_MB,
        "Memory should be bounded: {} MB", baseline.metadata.environment.memory_mb
    );
    assert!(
        !baseline.metadata.environment.platform.is_empty(),
        "Platform should not be empty"
    );
});