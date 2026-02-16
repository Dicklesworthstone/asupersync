//! Benchmark runner for conformance performance comparisons.

use crate::bench::report::{render_console_summary, write_html_report, write_json_report};
use crate::bench::stats::{Comparison, Stats};
use crate::bench::{BenchCategory, Benchmark};
use crate::logging::{LogCollector, LogEntry, LogLevel};
use crate::RuntimeInterface;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Benchmark runner configuration.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Extra warmup multiplier beyond the benchmark spec.
    pub warmup_multiplier: f32,
    /// Minimum samples regardless of the benchmark spec.
    pub min_samples: u32,
    /// Maximum time per benchmark (0 = no limit).
    pub max_time: Duration,
    /// Minimum log level to record.
    pub log_level: LogLevel,
    /// Output options for summaries.
    pub output: BenchOutput,
    /// Optional regression checking against a baseline report.
    pub regression: Option<RegressionConfig>,
    /// Whether to collect allocation statistics (if runtime supports it).
    pub collect_allocations: bool,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            warmup_multiplier: 1.0,
            min_samples: 10,
            max_time: Duration::from_secs(5),
            log_level: LogLevel::Info,
            output: BenchOutput::None,
            regression: None,
            collect_allocations: true,
        }
    }
}

/// Output targets for benchmark summaries.
#[derive(Debug, Clone)]
pub enum BenchOutput {
    /// No output side effects.
    None,
    /// Render a console-friendly summary string.
    Console,
    /// Write a JSON report to the provided path.
    Json(PathBuf),
    /// Write an HTML report to the provided path.
    Html(PathBuf),
    /// Write both JSON and HTML reports.
    All { json: PathBuf, html: PathBuf },
}

/// Snapshot of allocation counters for a benchmark.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BenchAllocSnapshot {
    pub allocations: u64,
    pub deallocations: u64,
    pub bytes_allocated: u64,
    pub bytes_deallocated: u64,
}

impl BenchAllocSnapshot {
    fn delta(before: &Self, after: &Self) -> Self {
        Self {
            allocations: after.allocations.saturating_sub(before.allocations),
            deallocations: after.deallocations.saturating_sub(before.deallocations),
            bytes_allocated: after.bytes_allocated.saturating_sub(before.bytes_allocated),
            bytes_deallocated: after
                .bytes_deallocated
                .saturating_sub(before.bytes_deallocated),
        }
    }
}

/// Aggregated allocation statistics for a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchAllocStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub total_bytes_allocated: u64,
    pub total_bytes_deallocated: u64,
    pub sample_count: usize,
    pub avg_allocations: f64,
    pub avg_deallocations: f64,
    pub avg_bytes_allocated: f64,
    pub avg_bytes_deallocated: f64,
}

impl BenchAllocStats {
    fn from_deltas(deltas: &[BenchAllocSnapshot]) -> Option<Self> {
        if deltas.is_empty() {
            return None;
        }

        let mut totals = BenchAllocSnapshot::default();
        for delta in deltas {
            totals.allocations = totals.allocations.saturating_add(delta.allocations);
            totals.deallocations = totals.deallocations.saturating_add(delta.deallocations);
            totals.bytes_allocated = totals.bytes_allocated.saturating_add(delta.bytes_allocated);
            totals.bytes_deallocated = totals
                .bytes_deallocated
                .saturating_add(delta.bytes_deallocated);
        }

        let sample_count = deltas.len();
        let divisor = sample_count as f64;
        Some(Self {
            total_allocations: totals.allocations,
            total_deallocations: totals.deallocations,
            total_bytes_allocated: totals.bytes_allocated,
            total_bytes_deallocated: totals.bytes_deallocated,
            sample_count,
            avg_allocations: totals.allocations as f64 / divisor,
            avg_deallocations: totals.deallocations as f64 / divisor,
            avg_bytes_allocated: totals.bytes_allocated as f64 / divisor,
            avg_bytes_deallocated: totals.bytes_deallocated as f64 / divisor,
        })
    }
}

/// Thresholds for regression checks.
#[derive(Debug, Clone)]
pub struct BenchThresholds {
    /// Max ratio (current/baseline) for mean latency.
    pub mean_ratio: Option<f64>,
    /// Max ratio (current/baseline) for p95 latency.
    pub p95_ratio: Option<f64>,
    /// Max ratio (current/baseline) for p99 latency.
    pub p99_ratio: Option<f64>,
    /// Max ratio (current/baseline) for allocation counts.
    pub allocations_ratio: Option<f64>,
}

impl Default for BenchThresholds {
    fn default() -> Self {
        Self {
            mean_ratio: Some(1.10),
            p95_ratio: Some(1.15),
            p99_ratio: Some(1.25),
            allocations_ratio: Some(1.10),
        }
    }
}

/// Regression config for benchmark runs.
#[derive(Debug, Clone)]
pub struct RegressionConfig {
    pub baseline: PathBuf,
    pub thresholds: BenchThresholds,
    pub missing_baseline_is_error: bool,
}

/// Result of a regression check for a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionMetric {
    pub metric: String,
    pub baseline: u64,
    pub current: u64,
    pub ratio: f64,
    pub threshold: f64,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionCheck {
    pub passed: bool,
    pub metrics: Vec<RegressionMetric>,
}

/// Result of running a single benchmark for one runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRunResult {
    pub benchmark_id: String,
    pub benchmark_name: String,
    pub category: BenchCategory,
    pub samples: Vec<Duration>,
    pub stats: Option<Stats>,
    #[serde(default)]
    pub alloc_stats: Option<BenchAllocStats>,
    #[serde(default)]
    pub regression: Option<RegressionCheck>,
    pub error: Option<String>,
    pub logs: Vec<LogEntry>,
}

/// Summary of a benchmark run for one runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRunSummary {
    pub runtime_name: String,
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub duration_ms: u64,
    pub results: Vec<BenchRunResult>,
    pub console_summary: Option<String>,
}

impl BenchRunSummary {
    /// Create an empty summary.
    pub fn new(runtime_name: impl Into<String>) -> Self {
        Self {
            runtime_name: runtime_name.into(),
            total: 0,
            completed: 0,
            failed: 0,
            duration_ms: 0,
            results: Vec::new(),
            console_summary: None,
        }
    }
}

/// Result of comparing two runtimes on the same benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchComparisonResult {
    pub benchmark_id: String,
    pub benchmark_name: String,
    pub category: BenchCategory,
    pub runtime_a: BenchRunResult,
    pub runtime_b: BenchRunResult,
    pub comparison: Option<Comparison>,
}

/// Summary of benchmark comparison between two runtimes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchComparisonSummary {
    pub runtime_a_name: String,
    pub runtime_b_name: String,
    pub total: usize,
    pub compared: usize,
    pub failed: usize,
    pub duration_ms: u64,
    pub results: Vec<BenchComparisonResult>,
}

/// Benchmark runner for a single runtime implementation.
pub struct BenchRunner<'a, R: RuntimeInterface> {
    runtime: &'a R,
    runtime_name: String,
    config: BenchConfig,
}

impl<'a, R: RuntimeInterface> BenchRunner<'a, R> {
    /// Create a new benchmark runner.
    pub fn new(runtime: &'a R, runtime_name: impl Into<String>, config: BenchConfig) -> Self {
        Self {
            runtime,
            runtime_name: runtime_name.into(),
            config,
        }
    }

    /// Run all benchmarks and return a summary.
    pub fn run_all(&self, benchmarks: &[Benchmark<R>]) -> BenchRunSummary {
        let start = Instant::now();
        let mut summary = BenchRunSummary::new(self.runtime_name.clone());
        summary.total = benchmarks.len();
        let (baseline_map, baseline_error) = match &self.config.regression {
            Some(config) => match load_baseline(&config.baseline) {
                Ok(baseline) => (Some(build_baseline_map(&baseline)), None),
                Err(err) => (None, Some(err.to_string())),
            },
            None => (None, None),
        };

        for bench in benchmarks {
            let mut result = self.run_single(bench);

            if let Some(regression_config) = &self.config.regression {
                match &baseline_map {
                    Some(baseline) => {
                        let baseline_result = baseline.get(bench.id);
                        if let Some(check) =
                            evaluate_regression(&result, baseline_result, regression_config)
                        {
                            if !check.passed && result.error.is_none() {
                                result.error = Some(regression_error_message(&check));
                            }
                            result.regression = Some(check);
                        }
                    }
                    None => {
                        if regression_config.missing_baseline_is_error && result.error.is_none() {
                            result.error = Some(format!(
                                "Missing baseline report: {}",
                                regression_config.baseline.display()
                            ));
                        }
                    }
                }
            }

            if result.error.is_some() {
                summary.failed += 1;
            } else {
                summary.completed += 1;
            }
            summary.results.push(result);
        }

        summary.duration_ms = start.elapsed().as_millis() as u64;

        match &self.config.output {
            BenchOutput::None => {}
            BenchOutput::Console => {
                summary.console_summary = Some(render_console_summary(&summary));
            }
            BenchOutput::Json(path) => {
                if let Err(err) = write_json_report(&summary, path) {
                    summary.console_summary = Some(format!(
                        "Failed to write JSON report to {:?}: {}",
                        path, err
                    ));
                }
            }
            BenchOutput::Html(path) => {
                if let Err(err) = write_html_report(&summary, path) {
                    summary.console_summary = Some(format!(
                        "Failed to write HTML report to {:?}: {}",
                        path, err
                    ));
                }
            }
            BenchOutput::All { json, html } => {
                if let Err(err) = write_json_report(&summary, json) {
                    summary.console_summary = Some(format!(
                        "Failed to write JSON report to {:?}: {}",
                        json, err
                    ));
                }
                if let Err(err) = write_html_report(&summary, html) {
                    summary.console_summary = Some(format!(
                        "Failed to write HTML report to {:?}: {}",
                        html, err
                    ));
                }
            }
        }

        if let Some(err) = baseline_error {
            let note = format!("Baseline load failed: {err}");
            summary.console_summary = Some(match summary.console_summary.take() {
                Some(mut existing) => {
                    existing.push('\n');
                    existing.push_str(&note);
                    existing
                }
                None => note,
            });
        }

        summary
    }

    fn run_single(&self, bench: &Benchmark<R>) -> BenchRunResult {
        let collector = LogCollector::new(self.config.log_level);
        collector.start();
        collector.info(format!("Starting benchmark {}", bench.id));

        let warmup = scaled_warmup(bench.warmup, self.config.warmup_multiplier);
        for _ in 0..warmup {
            let _ = (bench.bench_fn)(self.runtime);
        }

        let mut samples = Vec::new();
        let mut alloc_deltas = Vec::new();
        let mut error = None;
        let min_samples = self.config.min_samples.max(1);
        let target_samples = bench.iterations.max(min_samples);
        let start = Instant::now();

        for i in 0..target_samples {
            let alloc_before = if self.config.collect_allocations {
                self.runtime.bench_alloc_snapshot()
            } else {
                None
            };
            let duration = (bench.bench_fn)(self.runtime);
            if self.config.collect_allocations {
                let alloc_after = self.runtime.bench_alloc_snapshot();
                if let (Some(before), Some(after)) = (alloc_before, alloc_after) {
                    alloc_deltas.push(BenchAllocSnapshot::delta(&before, &after));
                }
            }
            collector.debug(format!(
                "sample {} duration_us={} benchmark_id={}",
                i,
                duration.as_micros(),
                bench.id
            ));
            samples.push(duration);

            if self.config.max_time != Duration::ZERO
                && samples.len() >= min_samples as usize
                && start.elapsed() >= self.config.max_time
            {
                collector.warn(format!(
                    "Reached max time {:?} after {} samples for {}",
                    self.config.max_time,
                    samples.len(),
                    bench.id
                ));
                break;
            }
        }

        let stats = match Stats::from_samples(&samples) {
            Ok(stats) => {
                if stats.cv() > 0.5 {
                    collector.warn(format!(
                        "High variance detected (cv={:.2}) for {}",
                        stats.cv(),
                        bench.id
                    ));
                }
                Some(stats)
            }
            Err(err) => {
                error = Some(err.to_string());
                collector.error(format!("Failed to compute stats for {}: {}", bench.id, err));
                None
            }
        };
        let alloc_stats = BenchAllocStats::from_deltas(&alloc_deltas);

        collector.info(format!("Benchmark {} complete", bench.id));

        BenchRunResult {
            benchmark_id: bench.id.to_string(),
            benchmark_name: bench.name.to_string(),
            category: bench.category,
            samples,
            stats,
            alloc_stats,
            regression: None,
            error,
            logs: collector.drain(),
        }
    }
}

fn load_baseline(path: &Path) -> io::Result<BenchRunSummary> {
    let data = fs::read(path)?;
    let summary: BenchRunSummary = serde_json::from_slice(&data)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    Ok(summary)
}

fn build_baseline_map(summary: &BenchRunSummary) -> HashMap<String, BenchRunResult> {
    summary
        .results
        .iter()
        .cloned()
        .map(|result| (result.benchmark_id.clone(), result))
        .collect()
}

fn evaluate_regression(
    current: &BenchRunResult,
    baseline: Option<&BenchRunResult>,
    config: &RegressionConfig,
) -> Option<RegressionCheck> {
    let current_stats = current.stats.as_ref()?;
    let baseline_stats = baseline.and_then(|b| b.stats.as_ref())?;

    let mut metrics = Vec::new();

    if let Some(threshold) = config.thresholds.mean_ratio {
        metrics.push(regression_metric_duration(
            "mean",
            baseline_stats.mean,
            current_stats.mean,
            threshold,
        ));
    }

    if let Some(threshold) = config.thresholds.p95_ratio {
        metrics.push(regression_metric_duration(
            "p95",
            baseline_stats.p95,
            current_stats.p95,
            threshold,
        ));
    }

    if let Some(threshold) = config.thresholds.p99_ratio {
        metrics.push(regression_metric_duration(
            "p99",
            baseline_stats.p99,
            current_stats.p99,
            threshold,
        ));
    }

    if let Some(threshold) = config.thresholds.allocations_ratio {
        if let (Some(current_alloc), Some(baseline_alloc)) = (
            current.alloc_stats.as_ref(),
            baseline.and_then(|b| b.alloc_stats.as_ref()),
        ) {
            metrics.push(regression_metric_count(
                "allocations",
                baseline_alloc.total_allocations,
                current_alloc.total_allocations,
                threshold,
            ));
        }
    }

    if metrics.is_empty() {
        return None;
    }

    let passed = metrics.iter().all(|metric| metric.passed);
    Some(RegressionCheck { passed, metrics })
}

fn regression_metric_duration(
    name: &str,
    baseline: Duration,
    current: Duration,
    threshold: f64,
) -> RegressionMetric {
    let baseline_nanos = duration_to_u64(baseline);
    let current_nanos = duration_to_u64(current);
    regression_metric_count(name, baseline_nanos, current_nanos, threshold)
}

fn regression_metric_count(
    name: &str,
    baseline: u64,
    current: u64,
    threshold: f64,
) -> RegressionMetric {
    let ratio = if baseline == 0 {
        if current == 0 {
            1.0
        } else {
            f64::INFINITY
        }
    } else {
        current as f64 / baseline as f64
    };

    let passed = ratio <= threshold;
    RegressionMetric {
        metric: name.to_string(),
        baseline,
        current,
        ratio,
        threshold,
        passed,
    }
}

fn regression_error_message(check: &RegressionCheck) -> String {
    let failures: Vec<String> = check
        .metrics
        .iter()
        .filter(|metric| !metric.passed)
        .map(|metric| {
            format!(
                "{} {:.2}x > {:.2}x",
                metric.metric, metric.ratio, metric.threshold
            )
        })
        .collect();

    if failures.is_empty() {
        "Regression check failed".to_string()
    } else {
        format!("Regression threshold exceeded: {}", failures.join(", "))
    }
}

fn duration_to_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Run comparison between two runtimes.
pub fn run_benchmark_comparison<RTA: RuntimeInterface, RTB: RuntimeInterface>(
    runtime_a: &RTA,
    runtime_a_name: &str,
    runtime_b: &RTB,
    runtime_b_name: &str,
    benches_a: &[Benchmark<RTA>],
    benches_b: &[Benchmark<RTB>],
    config: BenchConfig,
) -> BenchComparisonSummary {
    let start = Instant::now();
    let mut summary = BenchComparisonSummary {
        runtime_a_name: runtime_a_name.to_string(),
        runtime_b_name: runtime_b_name.to_string(),
        total: 0,
        compared: 0,
        failed: 0,
        duration_ms: 0,
        results: Vec::new(),
    };

    let benches_a_map: HashMap<&str, &Benchmark<RTA>> =
        benches_a.iter().map(|b| (b.id, b)).collect();
    let benches_b_map: HashMap<&str, &Benchmark<RTB>> =
        benches_b.iter().map(|b| (b.id, b)).collect();

    let common_ids: Vec<&str> = benches_a_map
        .keys()
        .filter(|id| benches_b_map.contains_key(*id))
        .copied()
        .collect();

    let runner_a = BenchRunner::new(runtime_a, runtime_a_name, config.clone());
    let runner_b = BenchRunner::new(runtime_b, runtime_b_name, config.clone());

    summary.total = common_ids.len();

    for id in common_ids {
        let bench_a = benches_a_map[id];
        let bench_b = benches_b_map[id];

        let result_a = runner_a.run_single(bench_a);
        let result_b = runner_b.run_single(bench_b);

        let comparison = match (&result_a.stats, &result_b.stats) {
            (Some(a), Some(b)) => Some(Comparison::compute(a, b)),
            _ => None,
        };

        if result_a.error.is_some() || result_b.error.is_some() {
            summary.failed += 1;
        } else {
            summary.compared += 1;
        }

        summary.results.push(BenchComparisonResult {
            benchmark_id: bench_a.id.to_string(),
            benchmark_name: bench_a.name.to_string(),
            category: bench_a.category,
            runtime_a: result_a,
            runtime_b: result_b,
            comparison,
        });
    }

    summary.duration_ms = start.elapsed().as_millis() as u64;
    summary
}

fn scaled_warmup(base: u32, multiplier: f32) -> u32 {
    if multiplier <= 0.0 || !multiplier.is_finite() || base == 0 {
        return 0;
    }
    let scaled = (base as f32) * multiplier;
    if !scaled.is_finite() || scaled <= 0.0 {
        return 0;
    }
    if scaled >= u32::MAX as f32 {
        return u32::MAX;
    }
    scaled.round() as u32
}
