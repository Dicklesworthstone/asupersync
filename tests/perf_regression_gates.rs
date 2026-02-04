//! Perf regression gate tests and helpers (bd-274qo).
//!
//! Validates the regression gate mechanism used in CI to prevent performance
//! regressions from landing. Tests exercise:
//!
//! - Baseline JSON parsing and schema validation
//! - Regression threshold logic (mean 1.10x, p95 1.15x, p99 1.25x)
//! - Smoke tests with synthetic baselines to verify gate behavior
//! - Edge cases: missing baselines, empty baselines, NaN/Inf values
//!
//! These tests do NOT run actual benchmarks — they validate the gate logic
//! itself using synthetic data so CI stays fast and deterministic.

use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::fs;
use std::path::Path;

// =========================================================================
// Baseline JSON schema (matches capture_baseline.sh output)
// =========================================================================

/// A single benchmark entry in the baseline JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineBenchmark {
    name: String,
    mean_ns: f64,
    median_ns: f64,
    #[serde(default)]
    std_dev_ns: f64,
    #[serde(default)]
    p95_ns: Option<f64>,
    #[serde(default)]
    p99_ns: Option<f64>,
}

/// Root structure of baseline JSON files.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineReport {
    generated_at: String,
    benchmarks: Vec<BaselineBenchmark>,
}

// =========================================================================
// Regression gate logic (mirrors capture_baseline.sh --compare)
// =========================================================================

/// Thresholds for regression detection, matching docs/benchmarking.md.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone)]
struct RegressionThresholds {
    mean_ratio: f64,
    p95_ratio: f64,
    p99_ratio: f64,
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            mean_ratio: 1.10,
            p95_ratio: 1.15,
            p99_ratio: 1.25,
        }
    }
}

/// Result of checking a single metric for regression.
#[derive(Debug, Clone)]
struct MetricCheck {
    metric_name: String,
    baseline_ns: f64,
    current_ns: f64,
    ratio: f64,
    threshold: f64,
    passed: bool,
}

impl MetricCheck {
    fn new(metric_name: &str, baseline_ns: f64, current_ns: f64, threshold: f64) -> Self {
        let ratio = if baseline_ns <= 0.0 {
            if current_ns <= 0.0 {
                1.0
            } else {
                f64::INFINITY
            }
        } else {
            current_ns / baseline_ns
        };
        let passed = ratio.is_finite() && ratio <= threshold;
        Self {
            metric_name: metric_name.to_string(),
            baseline_ns,
            current_ns,
            ratio,
            threshold,
            passed,
        }
    }
}

/// Full regression check for a benchmark against a baseline.
#[derive(Debug)]
struct BenchmarkRegressionResult {
    benchmark_name: String,
    checks: Vec<MetricCheck>,
    passed: bool,
}

/// Compare a current benchmark against a baseline entry.
fn check_regression(
    baseline: &BaselineBenchmark,
    current: &BaselineBenchmark,
    thresholds: &RegressionThresholds,
) -> BenchmarkRegressionResult {
    let mut checks = Vec::new();

    checks.push(MetricCheck::new(
        "mean_ns",
        baseline.mean_ns,
        current.mean_ns,
        thresholds.mean_ratio,
    ));

    if let (Some(bp95), Some(cp95)) = (baseline.p95_ns, current.p95_ns) {
        checks.push(MetricCheck::new("p95_ns", bp95, cp95, thresholds.p95_ratio));
    }

    if let (Some(bp99), Some(cp99)) = (baseline.p99_ns, current.p99_ns) {
        checks.push(MetricCheck::new("p99_ns", bp99, cp99, thresholds.p99_ratio));
    }

    let passed = checks.iter().all(|c| c.passed);
    BenchmarkRegressionResult {
        benchmark_name: baseline.name.clone(),
        checks,
        passed,
    }
}

/// Run regression checks across all matching benchmarks.
fn run_regression_gate(
    baseline: &BaselineReport,
    current: &BaselineReport,
    thresholds: &RegressionThresholds,
) -> Vec<BenchmarkRegressionResult> {
    let baseline_map: std::collections::HashMap<&str, &BaselineBenchmark> = baseline
        .benchmarks
        .iter()
        .map(|b| (b.name.as_str(), b))
        .collect();

    current
        .benchmarks
        .iter()
        .filter_map(|cur| {
            baseline_map
                .get(cur.name.as_str())
                .map(|base| check_regression(base, cur, thresholds))
        })
        .collect()
}

/// Generate a human-readable regression report.
fn format_regression_report(results: &[BenchmarkRegressionResult]) -> String {
    let mut report = String::new();
    let failures: Vec<&BenchmarkRegressionResult> = results.iter().filter(|r| !r.passed).collect();

    if failures.is_empty() {
        report.push_str("All regression checks passed.\n");
    } else {
        let _ = writeln!(
            report,
            "REGRESSION DETECTED: {} benchmark(s) exceeded thresholds\n",
            failures.len()
        );
        for fail in &failures {
            let _ = writeln!(report, "  {}:", fail.benchmark_name);
            for check in &fail.checks {
                if !check.passed {
                    let _ = writeln!(
                        report,
                        "    {} {:.2}x > {:.2}x (baseline={:.1}ns, current={:.1}ns)\n",
                        check.metric_name,
                        check.ratio,
                        check.threshold,
                        check.baseline_ns,
                        check.current_ns,
                    );
                }
            }
        }
    }

    report
}

// =========================================================================
// Helper: create synthetic baseline/current reports
// =========================================================================

fn make_benchmark(name: &str, mean_ns: f64, median_ns: f64) -> BaselineBenchmark {
    BaselineBenchmark {
        name: name.to_string(),
        mean_ns,
        median_ns,
        std_dev_ns: mean_ns * 0.1,
        p95_ns: Some(mean_ns * 1.3),
        p99_ns: Some(mean_ns * 1.8),
    }
}

fn make_report(benchmarks: Vec<BaselineBenchmark>) -> BaselineReport {
    BaselineReport {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        benchmarks,
    }
}

// =========================================================================
// Tests: baseline JSON parsing
// =========================================================================

#[test]
fn parse_baseline_json_from_disk() {
    let baseline_path = Path::new("baselines/baseline_latest.json");
    if !baseline_path.exists() {
        // No baseline on disk — skip gracefully (CI may not have run benches).
        eprintln!("SKIP: no baseline at {}", baseline_path.display());
        return;
    }
    let data = fs::read_to_string(baseline_path).expect("read baseline file");
    let report: BaselineReport = serde_json::from_str(&data).expect("parse baseline JSON");

    assert!(!report.generated_at.is_empty(), "generated_at must be set");
    assert!(
        !report.benchmarks.is_empty(),
        "baseline must contain benchmarks"
    );

    for bench in &report.benchmarks {
        assert!(!bench.name.is_empty(), "benchmark name must not be empty");
        assert!(
            bench.mean_ns.is_finite() && bench.mean_ns >= 0.0,
            "mean_ns must be finite and non-negative for {}",
            bench.name
        );
        assert!(
            bench.median_ns.is_finite() && bench.median_ns >= 0.0,
            "median_ns must be finite and non-negative for {}",
            bench.name
        );
    }
}

#[test]
fn parse_synthetic_baseline_roundtrip() {
    let report = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("scheduler/priority", 250.0, 248.0),
    ]);

    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let parsed: BaselineReport = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(parsed.benchmarks.len(), 2);
    assert_eq!(parsed.benchmarks[0].name, "arena/insert");
    assert!((parsed.benchmarks[0].mean_ns - 14.0).abs() < 0.001);
}

#[test]
fn parse_baseline_without_percentiles() {
    let json = r#"{
        "generated_at": "2026-01-01T00:00:00Z",
        "benchmarks": [
            {"name": "test/bench", "mean_ns": 100.0, "median_ns": 95.0, "std_dev_ns": 10.0}
        ]
    }"#;
    let report: BaselineReport = serde_json::from_str(json).expect("parse");
    assert_eq!(report.benchmarks.len(), 1);
    assert!(report.benchmarks[0].p95_ns.is_none());
    assert!(report.benchmarks[0].p99_ns.is_none());
}

// =========================================================================
// Tests: regression gate logic
// =========================================================================

#[test]
fn gate_passes_on_identical_results() {
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("scheduler/priority", 250.0, 248.0),
    ]);
    let current = baseline.clone();
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|r| r.passed),
        "identical results must pass"
    );
}

#[test]
fn gate_passes_on_improvement() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    // 20% faster
    let current = make_report(vec![make_benchmark("arena/insert", 11.2, 11.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "improvements must pass");
}

#[test]
fn gate_passes_on_small_regression_within_threshold() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // 8% regression — within 10% mean threshold
    let current = make_report(vec![make_benchmark("arena/insert", 108.0, 103.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].passed,
        "8% regression should be within 10% mean threshold"
    );
}

#[test]
fn gate_fails_on_mean_regression() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // 15% regression on mean — exceeds 10% threshold
    let current = make_report(vec![make_benchmark("arena/insert", 115.0, 110.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed, "15% mean regression must fail");

    let failed_checks: Vec<&MetricCheck> = results[0].checks.iter().filter(|c| !c.passed).collect();
    assert!(
        failed_checks.iter().any(|c| c.metric_name == "mean_ns"),
        "mean_ns check must fail"
    );
}

#[test]
fn gate_fails_on_p95_regression() {
    // Construct baselines where mean is fine but p95 exceeds threshold.
    let mut baseline_bench = make_benchmark("scheduler/priority", 100.0, 95.0);
    baseline_bench.p95_ns = Some(130.0);
    let mut current_bench = make_benchmark("scheduler/priority", 105.0, 100.0);
    // p95 grows from 130 to 155 → 1.19x, exceeds 1.15x
    current_bench.p95_ns = Some(155.0);

    let baseline = make_report(vec![baseline_bench]);
    let current = make_report(vec![current_bench]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed, "p95 regression must fail");

    let failed_checks: Vec<&MetricCheck> = results[0].checks.iter().filter(|c| !c.passed).collect();
    assert!(
        failed_checks.iter().any(|c| c.metric_name == "p95_ns"),
        "p95_ns check must fail"
    );
}

#[test]
fn gate_fails_on_p99_regression() {
    let mut baseline_bench = make_benchmark("scheduler/priority", 100.0, 95.0);
    baseline_bench.p99_ns = Some(180.0);
    let mut current_bench = make_benchmark("scheduler/priority", 105.0, 100.0);
    // p99 grows from 180 to 230 → 1.28x, exceeds 1.25x
    current_bench.p99_ns = Some(230.0);

    let baseline = make_report(vec![baseline_bench]);
    let current = make_report(vec![current_bench]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    assert!(!results[0].passed, "p99 regression must fail");
}

#[test]
fn gate_handles_missing_benchmark_in_current() {
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("arena/get_hit", 1.0, 0.9),
    ]);
    // Current only has one benchmark
    let current = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    // Only matching benchmarks are compared
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn gate_handles_new_benchmark_in_current() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let current = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("arena/new_bench", 5.0, 4.8),
    ]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    // New benchmarks without baselines are skipped
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn gate_handles_empty_baseline() {
    let baseline = make_report(vec![]);
    let current = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert!(results.is_empty(), "no comparisons with empty baseline");
}

#[test]
fn gate_handles_empty_current() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let current = make_report(vec![]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert!(results.is_empty(), "no comparisons with empty current");
}

// =========================================================================
// Tests: edge cases
// =========================================================================

#[test]
fn gate_handles_zero_baseline() {
    let baseline = make_report(vec![make_benchmark("zero/bench", 0.0, 0.0)]);
    let current = make_report(vec![make_benchmark("zero/bench", 5.0, 4.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    // Zero baseline with non-zero current should fail (infinite ratio).
    assert!(!results[0].passed);
}

#[test]
fn gate_handles_zero_both() {
    let baseline = make_report(vec![make_benchmark("zero/bench", 0.0, 0.0)]);
    let current = make_report(vec![make_benchmark("zero/bench", 0.0, 0.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    // 0/0 → ratio 1.0, should pass.
    assert!(results[0].passed);
}

#[test]
fn custom_thresholds_are_respected() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // 4% regression
    let current = make_report(vec![make_benchmark("arena/insert", 104.0, 99.0)]);

    // Strict threshold: 3%
    let strict = RegressionThresholds {
        mean_ratio: 1.03,
        p95_ratio: 1.05,
        p99_ratio: 1.10,
    };
    let results = run_regression_gate(&baseline, &current, &strict);
    assert!(!results[0].passed, "4% regression must fail 3% threshold");

    // Lenient threshold: 5%
    let lenient = RegressionThresholds {
        mean_ratio: 1.05,
        p95_ratio: 1.10,
        p99_ratio: 1.20,
    };
    let results = run_regression_gate(&baseline, &current, &lenient);
    assert!(results[0].passed, "4% regression should pass 5% threshold");
}

#[test]
fn boundary_regression_exactly_at_threshold() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    // Exactly 10% regression — at the boundary
    let current = make_report(vec![make_benchmark("arena/insert", 110.0, 104.5)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 1);
    // 1.10 <= 1.10 → passes (threshold is inclusive)
    assert!(results[0].passed, "exactly-at-threshold should pass");
}

// =========================================================================
// Tests: report formatting
// =========================================================================

#[test]
fn report_shows_pass_on_clean_run() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 14.0, 13.9)]);
    let current = baseline.clone();
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    let report = format_regression_report(&results);
    assert!(
        report.contains("All regression checks passed"),
        "clean run report: {report}"
    );
}

#[test]
fn report_shows_failure_details() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    let current = make_report(vec![make_benchmark("arena/insert", 120.0, 115.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    let report = format_regression_report(&results);
    assert!(
        report.contains("REGRESSION DETECTED"),
        "regression report: {report}"
    );
    assert!(
        report.contains("arena/insert"),
        "report must name the benchmark: {report}"
    );
    assert!(
        report.contains("mean_ns"),
        "report must name the metric: {report}"
    );
}

// =========================================================================
// Tests: multiple benchmarks in one gate check
// =========================================================================

#[test]
fn gate_multiple_benchmarks_mixed_results() {
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 100.0, 95.0),
        make_benchmark("arena/get_hit", 1.0, 0.9),
        make_benchmark("scheduler/priority", 250.0, 248.0),
    ]);
    let current = make_report(vec![
        make_benchmark("arena/insert", 120.0, 115.0), // 20% regression → fail
        make_benchmark("arena/get_hit", 0.95, 0.88),  // improvement → pass
        make_benchmark("scheduler/priority", 255.0, 253.0), // 2% → pass
    ]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    assert_eq!(results.len(), 3);

    let passed = results.iter().filter(|r| r.passed).count();
    let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();

    assert_eq!(passed, 2, "2 benchmarks should pass");
    assert_eq!(failed.len(), 1, "1 benchmark should fail");
    assert_eq!(failed[0].benchmark_name, "arena/insert");
}

// =========================================================================
// Tests: conformance with on-disk baseline (if available)
// =========================================================================

#[test]
fn gate_on_disk_baseline_self_check() {
    let baseline_path = Path::new("baselines/baseline_latest.json");
    if !baseline_path.exists() {
        eprintln!("SKIP: no baseline at {}", baseline_path.display());
        return;
    }
    let data = fs::read_to_string(baseline_path).expect("read baseline");
    let report: BaselineReport = serde_json::from_str(&data).expect("parse baseline");

    // Self-comparison must always pass.
    let thresholds = RegressionThresholds::default();
    let results = run_regression_gate(&report, &report, &thresholds);

    for result in &results {
        assert!(
            result.passed,
            "self-comparison must pass for {}",
            result.benchmark_name
        );
    }
}

// =========================================================================
// Tests: synthetic regression smoke test (bd-274qo acceptance criteria)
// =========================================================================

#[test]
fn smoke_test_synthetic_regression_detected() {
    // Simulate a real CI scenario: current run has a regression on one bench.
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("arena/get_hit", 1.0, 0.9),
        make_benchmark("scheduler/local_queue/push_pop", 45.0, 43.0),
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1340.0, 1320.0),
        make_benchmark("budget/combine", 10.0, 10.0),
    ]);

    let current = make_report(vec![
        make_benchmark("arena/insert", 14.2, 14.0), // +1.4% → pass
        make_benchmark("arena/get_hit", 1.02, 0.92), // +2% → pass
        make_benchmark("scheduler/local_queue/push_pop", 55.0, 53.0), // +22% → FAIL
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1360.0, 1340.0), // +1.5% → pass
        make_benchmark("budget/combine", 10.5, 10.3),                                 // +5% → pass
    ]);

    let thresholds = RegressionThresholds::default();
    let results = run_regression_gate(&baseline, &current, &thresholds);

    let all_passed = results.iter().all(|r| r.passed);
    assert!(!all_passed, "gate must detect synthetic regression");

    let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].benchmark_name, "scheduler/local_queue/push_pop");

    let report = format_regression_report(&results);
    assert!(report.contains("REGRESSION DETECTED"));
    assert!(report.contains("scheduler/local_queue/push_pop"));
}

#[test]
fn smoke_test_clean_run_passes_gate() {
    // Simulate CI with no regressions (small noise within tolerance).
    let baseline = make_report(vec![
        make_benchmark("arena/insert", 14.0, 13.9),
        make_benchmark("scheduler/local_queue/push_pop", 45.0, 43.0),
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1340.0, 1320.0),
    ]);

    let current = make_report(vec![
        make_benchmark("arena/insert", 14.5, 14.2), // +3.6%
        make_benchmark("scheduler/local_queue/push_pop", 47.0, 45.5), // +4.4%
        make_benchmark("scheduler/priority/batch_schedule_ready/10", 1380.0, 1360.0), // +3.0%
    ]);

    let thresholds = RegressionThresholds::default();
    let results = run_regression_gate(&baseline, &current, &thresholds);

    let all_passed = results.iter().all(|r| r.passed);
    assert!(all_passed, "normal noise should pass the gate");

    let report = format_regression_report(&results);
    assert!(report.contains("All regression checks passed"));
}

// =========================================================================
// Tests: JSON serialization of regression results (for CI artifacts)
// =========================================================================

#[derive(Debug, Serialize, Deserialize)]
struct GateReport {
    passed: bool,
    total_benchmarks: usize,
    regressions: Vec<RegressionDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegressionDetail {
    benchmark: String,
    metric: String,
    ratio: f64,
    threshold: f64,
    baseline_ns: f64,
    current_ns: f64,
}

fn build_gate_report(results: &[BenchmarkRegressionResult]) -> GateReport {
    let mut regressions = Vec::new();
    for result in results {
        for check in &result.checks {
            if !check.passed {
                regressions.push(RegressionDetail {
                    benchmark: result.benchmark_name.clone(),
                    metric: check.metric_name.clone(),
                    ratio: check.ratio,
                    threshold: check.threshold,
                    baseline_ns: check.baseline_ns,
                    current_ns: check.current_ns,
                });
            }
        }
    }
    let passed = regressions.is_empty();
    GateReport {
        passed,
        total_benchmarks: results.len(),
        regressions,
    }
}

#[test]
fn gate_report_json_roundtrip() {
    let baseline = make_report(vec![make_benchmark("arena/insert", 100.0, 95.0)]);
    let current = make_report(vec![make_benchmark("arena/insert", 115.0, 110.0)]);
    let thresholds = RegressionThresholds::default();

    let results = run_regression_gate(&baseline, &current, &thresholds);
    let gate_report = build_gate_report(&results);

    assert!(!gate_report.passed);
    assert_eq!(gate_report.total_benchmarks, 1);
    assert_eq!(gate_report.regressions.len(), 1);

    let json = serde_json::to_string_pretty(&gate_report).expect("serialize gate report");
    let parsed: GateReport = serde_json::from_str(&json).expect("deserialize gate report");
    assert!(!parsed.passed);
    assert_eq!(parsed.regressions[0].benchmark, "arena/insert");
}
