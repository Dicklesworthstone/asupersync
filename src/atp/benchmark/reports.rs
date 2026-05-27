//! Benchmark reporting and metrics analysis.

use crate::atp::benchmark::BenchmarkEnvironment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// Individual benchmark metrics for a single iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    /// Total wall-clock time
    pub wall_time: Duration,
    /// CPU time used (if measurable)
    pub cpu_time: Option<Duration>,
    /// Peak memory usage in bytes
    pub memory_peak: Option<u64>,
    /// Logical bytes transferred
    pub bytes_transferred: u64,
    /// Actual bytes on wire (after compression, with protocol overhead)
    pub bytes_on_wire: Option<u64>,
    /// Whether transfer completed successfully with verification
    pub verified_completion: bool,
    /// Time to first usable output (for streaming)
    pub first_usable_output: Option<Duration>,
    /// Time to resume after interruption (if applicable)
    pub resume_time: Option<Duration>,
    /// Disk amplification ratio for committed bytes versus logical payload.
    pub disk_amplification_ratio: Option<f64>,
    /// Whether a failed run produced enough evidence to reproduce the failure.
    pub failure_reproducible: Option<bool>,
    /// Failure mode if transfer failed
    pub failure_mode: Option<String>,
}

impl BenchmarkMetrics {
    /// Calculate effective throughput in bytes per second.
    #[must_use]
    pub fn throughput_bps(&self) -> Option<f64> {
        if self.verified_completion && self.wall_time.as_secs_f64() > 0.0 {
            Some(self.bytes_transferred as f64 / self.wall_time.as_secs_f64())
        } else {
            None
        }
    }

    /// Calculate compression ratio if available.
    #[must_use]
    pub fn compression_ratio(&self) -> Option<f64> {
        self.bytes_on_wire
            .map(|on_wire| self.bytes_transferred as f64 / on_wire as f64)
    }

    /// Calculate CPU efficiency (bytes per CPU second).
    #[must_use]
    pub fn cpu_efficiency(&self) -> Option<f64> {
        self.cpu_time.and_then(|cpu_time| {
            if cpu_time.as_secs_f64() > 0.0 {
                Some(self.bytes_transferred as f64 / cpu_time.as_secs_f64())
            } else {
                None
            }
        })
    }

    /// Calculate CPU milliseconds per GiB transferred.
    #[must_use]
    pub fn cpu_ms_per_gib(&self) -> Option<f64> {
        self.cpu_time.and_then(|cpu_time| {
            if self.bytes_transferred > 0 {
                let gib = self.bytes_transferred as f64 / 1_073_741_824.0;
                Some(cpu_time.as_secs_f64() * 1000.0 / gib)
            } else {
                None
            }
        })
    }
}

/// Complete benchmark result for a tool/profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Tool or profile name
    pub tool_name: String,
    /// Metrics from each iteration
    pub iterations: Vec<BenchmarkMetrics>,
    /// Environment metadata
    pub environment: BenchmarkEnvironment,
}

impl BenchmarkResult {
    /// Calculate aggregate statistics across iterations.
    #[must_use]
    pub fn aggregate_stats(&self) -> AggregateStats {
        let successful_iterations: Vec<&BenchmarkMetrics> = self
            .iterations
            .iter()
            .filter(|m| m.verified_completion)
            .collect();

        if successful_iterations.is_empty() {
            return AggregateStats::failed();
        }

        let wall_times: Vec<Duration> = successful_iterations.iter().map(|m| m.wall_time).collect();
        let first_usable_outputs: Vec<Duration> = successful_iterations
            .iter()
            .filter_map(|m| m.first_usable_output)
            .collect();
        let resume_times: Vec<Duration> = successful_iterations
            .iter()
            .filter_map(|m| m.resume_time)
            .collect();

        let throughputs: Vec<f64> = successful_iterations
            .iter()
            .filter_map(|m| m.throughput_bps())
            .collect();
        let cpu_ms_per_gib: Vec<f64> = successful_iterations
            .iter()
            .filter_map(|m| m.cpu_ms_per_gib())
            .collect();
        let disk_amplification_ratios: Vec<f64> = successful_iterations
            .iter()
            .filter_map(|m| m.disk_amplification_ratio)
            .collect();
        let bytes_on_wire: Vec<f64> = successful_iterations
            .iter()
            .filter_map(|m| m.bytes_on_wire.map(|value| value as f64))
            .collect();
        let reproducible_failures = self
            .iterations
            .iter()
            .filter(|m| !m.verified_completion)
            .filter(|m| m.failure_reproducible == Some(true))
            .count();
        let failed_iterations = self
            .iterations
            .iter()
            .filter(|m| !m.verified_completion)
            .count();

        AggregateStats {
            success_rate: successful_iterations.len() as f64 / self.iterations.len() as f64,
            mean_wall_time: mean_duration(&wall_times),
            median_wall_time: median_duration(&wall_times),
            std_dev_wall_time: std_dev_duration(&wall_times),
            mean_throughput: mean(&throughputs),
            median_throughput: median(&throughputs),
            std_dev_throughput: std_dev(&throughputs),
            mean_cpu_efficiency: mean(
                &successful_iterations
                    .iter()
                    .filter_map(|m| m.cpu_efficiency())
                    .collect::<Vec<_>>(),
            ),
            mean_cpu_ms_per_gib: mean(&cpu_ms_per_gib),
            mean_memory_peak: successful_iterations
                .iter()
                .filter_map(|m| m.memory_peak)
                .sum::<u64>() as f64
                / successful_iterations.len().max(1) as f64,
            mean_bytes_on_wire: mean(&bytes_on_wire),
            mean_first_usable_output: mean_duration(&first_usable_outputs),
            mean_resume_time: mean_duration(&resume_times),
            mean_disk_amplification_ratio: mean(&disk_amplification_ratios),
            failure_reproducibility_rate: if failed_iterations > 0 {
                reproducible_failures as f64 / failed_iterations as f64
            } else {
                1.0
            },
        }
    }

    /// Check if this result represents a successful benchmark.
    #[must_use]
    pub fn is_successful(&self) -> bool {
        !self.iterations.is_empty() && self.iterations.iter().any(|m| m.verified_completion)
    }
}

/// Aggregate statistics across multiple iterations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateStats {
    /// Fraction of iterations that completed successfully (0.0-1.0)
    pub success_rate: f64,
    /// Mean wall-clock time
    pub mean_wall_time: Duration,
    /// Median wall-clock time
    pub median_wall_time: Duration,
    /// Standard deviation of wall-clock time
    pub std_dev_wall_time: Duration,
    /// Mean throughput in bytes/second
    pub mean_throughput: f64,
    /// Median throughput in bytes/second
    pub median_throughput: f64,
    /// Standard deviation of throughput
    pub std_dev_throughput: f64,
    /// Mean CPU efficiency (bytes/cpu-second)
    pub mean_cpu_efficiency: f64,
    /// Mean CPU milliseconds per GiB transferred.
    pub mean_cpu_ms_per_gib: f64,
    /// Mean peak memory usage in bytes
    pub mean_memory_peak: f64,
    /// Mean bytes on wire across successful iterations.
    pub mean_bytes_on_wire: f64,
    /// Mean time to first usable output across successful iterations that report it.
    pub mean_first_usable_output: Duration,
    /// Mean resume time across successful interrupted iterations that report it.
    pub mean_resume_time: Duration,
    /// Mean disk amplification ratio across successful iterations that report it.
    pub mean_disk_amplification_ratio: f64,
    /// Fraction of failed iterations with replayable failure evidence.
    pub failure_reproducibility_rate: f64,
}

impl AggregateStats {
    /// Create stats representing complete failure.
    #[must_use]
    pub fn failed() -> Self {
        Self {
            success_rate: 0.0,
            mean_wall_time: Duration::ZERO,
            median_wall_time: Duration::ZERO,
            std_dev_wall_time: Duration::ZERO,
            mean_throughput: 0.0,
            median_throughput: 0.0,
            std_dev_throughput: 0.0,
            mean_cpu_efficiency: 0.0,
            mean_cpu_ms_per_gib: 0.0,
            mean_memory_peak: 0.0,
            mean_bytes_on_wire: 0.0,
            mean_first_usable_output: Duration::ZERO,
            mean_resume_time: Duration::ZERO,
            mean_disk_amplification_ratio: 0.0,
            failure_reproducibility_rate: 0.0,
        }
    }
}

/// Complete benchmark report comparing baseline tools with ATP profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Benchmark configuration used
    pub config_summary: ConfigSummary,
    /// Results from baseline tools
    pub baseline_results: BTreeMap<String, BenchmarkResult>,
    /// Results from ATP profiles
    pub atp_results: BTreeMap<String, BenchmarkResult>,
    /// Comparison analysis
    pub comparison: ComparisonReport,
    /// Report generation timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl BenchmarkReport {
    /// Create a new benchmark report.
    #[must_use]
    pub fn new(
        baseline_results: BTreeMap<String, BenchmarkResult>,
        atp_results: BTreeMap<String, BenchmarkResult>,
        data_size: u64,
        iterations: u32,
    ) -> Self {
        let comparison = ComparisonReport::analyze(&baseline_results, &atp_results);

        Self {
            config_summary: ConfigSummary {
                data_size,
                iterations,
            },
            baseline_results,
            atp_results,
            comparison,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Generate a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str(&format!(
            "Benchmark Report - {} bytes, {} iterations\n\n",
            self.config_summary.data_size, self.config_summary.iterations
        ));

        summary.push_str("Baseline Tools:\n");
        for (name, result) in &self.baseline_results {
            let stats = result.aggregate_stats();
            summary.push_str(&format!(
                "  {}: {:.2} MB/s (success rate: {:.1}%)\n",
                name,
                stats.mean_throughput / 1_000_000.0,
                stats.success_rate * 100.0
            ));
        }

        summary.push_str("\nATP Profiles:\n");
        for (name, result) in &self.atp_results {
            let stats = result.aggregate_stats();
            summary.push_str(&format!(
                "  {}: {:.2} MB/s (success rate: {:.1}%)\n",
                name,
                stats.mean_throughput / 1_000_000.0,
                stats.success_rate * 100.0
            ));
        }

        if let Some(best_baseline) = &self.comparison.best_baseline_performance {
            if let Some(best_atp) = &self.comparison.best_atp_performance {
                summary.push_str(&format!(
                    "\nBest Performance:\n  Baseline: {} ({:.2} MB/s)\n  ATP: {} ({:.2} MB/s)\n",
                    best_baseline.tool_name,
                    best_baseline.throughput / 1_000_000.0,
                    best_atp.tool_name,
                    best_atp.throughput / 1_000_000.0
                ));
            }
        }

        summary
    }

    /// Evaluate benchmark results against public regression thresholds.
    #[must_use]
    pub fn public_regression_report(
        &self,
        report_id: impl Into<String>,
        thresholds: &[MetricThreshold],
    ) -> PublicRegressionReport {
        let mut rows = Vec::new();

        for (name, result) in &self.baseline_results {
            rows.extend(evaluate_result_thresholds(
                &format!("baseline:{name}"),
                result,
                thresholds,
            ));
        }

        for (name, result) in &self.atp_results {
            rows.extend(evaluate_result_thresholds(
                &format!("atp:{name}"),
                result,
                thresholds,
            ));
        }

        PublicRegressionReport::new(report_id, rows)
    }
}

/// Schema version for ATP-L3 benchmark gate reports.
pub const PUBLIC_REGRESSION_REPORT_SCHEMA_VERSION: &str = "atp-l3-benchmark-gate-report-v1";

/// Threshold comparison operator for public benchmark gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdComparison {
    /// Observed value must be less than or equal to the threshold.
    LessThanOrEqual,
    /// Observed value must be greater than or equal to the threshold.
    GreaterThanOrEqual,
    /// Observed value must exactly equal the threshold.
    Equals,
}

impl ThresholdComparison {
    fn evaluate(self, observed: f64, threshold: f64) -> bool {
        match self {
            Self::LessThanOrEqual => observed <= threshold,
            Self::GreaterThanOrEqual => observed >= threshold,
            Self::Equals => (observed - threshold).abs() <= f64::EPSILON,
        }
    }
}

/// One metric threshold used by the public ATP benchmark regression report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricThreshold {
    /// Stable gate identifier.
    pub gate_id: String,
    /// Metric name from [`AggregateStats`].
    pub metric: String,
    /// Unit label for display and dashboards.
    pub unit: String,
    /// Comparison operator.
    pub comparison: ThresholdComparison,
    /// Threshold value.
    pub threshold: f64,
    /// Whether this threshold is required for release gates.
    pub required: bool,
}

impl MetricThreshold {
    /// Build a required threshold.
    #[must_use]
    pub fn required(
        gate_id: impl Into<String>,
        metric: impl Into<String>,
        unit: impl Into<String>,
        comparison: ThresholdComparison,
        threshold: f64,
    ) -> Self {
        Self {
            gate_id: gate_id.into(),
            metric: metric.into(),
            unit: unit.into(),
            comparison,
            threshold,
            required: true,
        }
    }
}

/// Status for one public benchmark regression gate row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkGateStatus {
    /// The observed value satisfied the threshold.
    Pass,
    /// The observed value violated the threshold.
    Fail,
    /// The row was intentionally skipped with a reason.
    Skipped,
}

/// Stable skip reason for a public benchmark regression gate row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkSkipReason {
    /// The result had no iterations.
    NoIterations,
    /// The result had no successful verified-completion iteration.
    NoSuccessfulIterations,
    /// The requested metric is not produced by this report.
    MetricUnavailable,
}

/// One machine-readable benchmark regression gate row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkGateRow {
    /// Stable gate identifier.
    pub gate_id: String,
    /// Baseline or ATP profile identifier.
    pub profile: String,
    /// Metric name.
    pub metric: String,
    /// Unit label.
    pub unit: String,
    /// Observed value, when available.
    pub observed: Option<f64>,
    /// Threshold value.
    pub threshold: f64,
    /// Comparison operator.
    pub comparison: ThresholdComparison,
    /// Whether the row is required for release signoff.
    pub required: bool,
    /// Gate status.
    pub status: BenchmarkGateStatus,
    /// Skip reason when `status` is skipped.
    pub skip_reason: Option<BenchmarkSkipReason>,
    /// Replay command or pointer for reproducing this profile run.
    pub replay_pointer: String,
}

/// Public ATP benchmark report suitable for dashboards and release gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRegressionReport {
    /// Stable schema version.
    pub schema_version: String,
    /// Caller-provided report identifier.
    pub report_id: String,
    /// Machine-readable gate rows.
    pub rows: Vec<BenchmarkGateRow>,
    /// Concise human-readable summary.
    pub human_summary: String,
}

impl PublicRegressionReport {
    fn new(report_id: impl Into<String>, rows: Vec<BenchmarkGateRow>) -> Self {
        let report_id = report_id.into();
        let passed = rows
            .iter()
            .filter(|row| row.status == BenchmarkGateStatus::Pass)
            .count();
        let failed = rows
            .iter()
            .filter(|row| row.status == BenchmarkGateStatus::Fail)
            .count();
        let skipped = rows
            .iter()
            .filter(|row| row.status == BenchmarkGateStatus::Skipped)
            .count();
        let human_summary = format!(
            "ATP-L3 public regression report {report_id}: {passed} passed, {failed} failed, {skipped} skipped"
        );

        Self {
            schema_version: PUBLIC_REGRESSION_REPORT_SCHEMA_VERSION.to_string(),
            report_id,
            rows,
            human_summary,
        }
    }
}

/// Configuration summary for report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSummary {
    /// Test data size in bytes
    pub data_size: u64,
    /// Number of iterations
    pub iterations: u32,
}

/// Comparison analysis between baseline and ATP results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// Best performing baseline tool
    pub best_baseline_performance: Option<PerformanceSummary>,
    /// Best performing ATP profile
    pub best_atp_performance: Option<PerformanceSummary>,
    /// Performance ratios (ATP/baseline)
    pub performance_ratios: Vec<PerformanceRatio>,
    /// Overall assessment
    pub assessment: String,
}

impl ComparisonReport {
    /// Analyze and compare baseline vs ATP results.
    #[must_use]
    pub fn analyze(
        baseline_results: &BTreeMap<String, BenchmarkResult>,
        atp_results: &BTreeMap<String, BenchmarkResult>,
    ) -> Self {
        let best_baseline = baseline_results
            .iter()
            .filter(|(_, result)| result.is_successful())
            .map(|(name, result)| {
                let stats = result.aggregate_stats();
                PerformanceSummary {
                    tool_name: name.clone(),
                    throughput: stats.mean_throughput,
                    wall_time: stats.mean_wall_time,
                    success_rate: stats.success_rate,
                }
            })
            .max_by(|a, b| {
                a.throughput
                    .partial_cmp(&b.throughput)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        let best_atp = atp_results
            .iter()
            .filter(|(_, result)| result.is_successful())
            .map(|(name, result)| {
                let stats = result.aggregate_stats();
                PerformanceSummary {
                    tool_name: name.clone(),
                    throughput: stats.mean_throughput,
                    wall_time: stats.mean_wall_time,
                    success_rate: stats.success_rate,
                }
            })
            .max_by(|a, b| {
                a.throughput
                    .partial_cmp(&b.throughput)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        let performance_ratios = Self::calculate_ratios(baseline_results, atp_results);
        let assessment = Self::generate_assessment(&best_baseline, &best_atp, &performance_ratios);

        Self {
            best_baseline_performance: best_baseline,
            best_atp_performance: best_atp,
            performance_ratios,
            assessment,
        }
    }

    fn calculate_ratios(
        baseline_results: &BTreeMap<String, BenchmarkResult>,
        atp_results: &BTreeMap<String, BenchmarkResult>,
    ) -> Vec<PerformanceRatio> {
        let mut ratios = Vec::new();

        for (baseline_name, baseline_result) in baseline_results {
            if !baseline_result.is_successful() {
                continue;
            }

            let baseline_stats = baseline_result.aggregate_stats();

            for (atp_name, atp_result) in atp_results {
                if !atp_result.is_successful() {
                    continue;
                }

                let atp_stats = atp_result.aggregate_stats();

                let throughput_ratio = if baseline_stats.mean_throughput > 0.0 {
                    atp_stats.mean_throughput / baseline_stats.mean_throughput
                } else {
                    0.0
                };

                let time_ratio = if baseline_stats.mean_wall_time.as_secs_f64() > 0.0 {
                    atp_stats.mean_wall_time.as_secs_f64()
                        / baseline_stats.mean_wall_time.as_secs_f64()
                } else {
                    0.0
                };

                ratios.push(PerformanceRatio {
                    baseline_tool: baseline_name.clone(),
                    atp_profile: atp_name.clone(),
                    throughput_ratio,
                    time_ratio,
                });
            }
        }

        ratios
    }

    fn generate_assessment(
        best_baseline: &Option<PerformanceSummary>,
        best_atp: &Option<PerformanceSummary>,
        ratios: &[PerformanceRatio],
    ) -> String {
        let comparison_count = ratios.len();
        match (best_baseline, best_atp) {
            (Some(baseline), Some(atp)) => {
                let ratio = atp.throughput / baseline.throughput;
                if ratio >= 1.1 {
                    format!(
                        "ATP outperforms baseline by {:.1}x across {} comparison(s)",
                        ratio, comparison_count
                    )
                } else if ratio >= 0.9 {
                    format!(
                        "ATP performance is comparable to baseline across {comparison_count} comparison(s)"
                    )
                } else {
                    format!(
                        "ATP underperforms baseline by {:.1}x across {} comparison(s)",
                        1.0 / ratio,
                        comparison_count
                    )
                }
            }
            (None, Some(_)) => "ATP succeeded where baseline tools failed".to_string(),
            (Some(_), None) => "Baseline tools succeeded but ATP failed".to_string(),
            (None, None) => "Both baseline and ATP failed".to_string(),
        }
    }
}

/// Performance summary for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    /// Tool or profile name
    pub tool_name: String,
    /// Mean throughput in bytes/second
    pub throughput: f64,
    /// Mean wall time
    pub wall_time: Duration,
    /// Success rate (0.0-1.0)
    pub success_rate: f64,
}

/// Performance ratio between ATP and baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRatio {
    /// Baseline tool name
    pub baseline_tool: String,
    /// ATP profile name
    pub atp_profile: String,
    /// ATP throughput / baseline throughput
    pub throughput_ratio: f64,
    /// ATP time / baseline time (lower is better)
    pub time_ratio: f64,
}

fn evaluate_result_thresholds(
    profile: &str,
    result: &BenchmarkResult,
    thresholds: &[MetricThreshold],
) -> Vec<BenchmarkGateRow> {
    let replay_pointer = format!("asupersync atp bench --profile {profile} --json");

    if result.iterations.is_empty() {
        return thresholds
            .iter()
            .map(|threshold| skipped_row(profile, threshold, BenchmarkSkipReason::NoIterations))
            .collect();
    }

    if !result.is_successful() {
        return thresholds
            .iter()
            .map(|threshold| {
                skipped_row(
                    profile,
                    threshold,
                    BenchmarkSkipReason::NoSuccessfulIterations,
                )
            })
            .collect();
    }

    let stats = result.aggregate_stats();
    thresholds
        .iter()
        .map(|threshold| match metric_value(&stats, &threshold.metric) {
            Some(observed) => BenchmarkGateRow {
                gate_id: threshold.gate_id.clone(),
                profile: profile.to_string(),
                metric: threshold.metric.clone(),
                unit: threshold.unit.clone(),
                observed: Some(observed),
                threshold: threshold.threshold,
                comparison: threshold.comparison,
                required: threshold.required,
                status: if threshold.comparison.evaluate(observed, threshold.threshold) {
                    BenchmarkGateStatus::Pass
                } else {
                    BenchmarkGateStatus::Fail
                },
                skip_reason: None,
                replay_pointer: replay_pointer.clone(),
            },
            None => skipped_row(profile, threshold, BenchmarkSkipReason::MetricUnavailable),
        })
        .collect()
}

fn skipped_row(
    profile: &str,
    threshold: &MetricThreshold,
    reason: BenchmarkSkipReason,
) -> BenchmarkGateRow {
    BenchmarkGateRow {
        gate_id: threshold.gate_id.clone(),
        profile: profile.to_string(),
        metric: threshold.metric.clone(),
        unit: threshold.unit.clone(),
        observed: None,
        threshold: threshold.threshold,
        comparison: threshold.comparison,
        required: threshold.required,
        status: BenchmarkGateStatus::Skipped,
        skip_reason: Some(reason),
        replay_pointer: format!("asupersync atp bench --profile {profile} --json"),
    }
}

fn metric_value(stats: &AggregateStats, metric: &str) -> Option<f64> {
    Some(match metric {
        "success_rate" | "verified_completion_rate" => stats.success_rate,
        "mean_wall_time_ms" => stats.mean_wall_time.as_secs_f64() * 1000.0,
        "median_wall_time_ms" => stats.median_wall_time.as_secs_f64() * 1000.0,
        "mean_throughput_bps" => stats.mean_throughput,
        "median_throughput_bps" => stats.median_throughput,
        "mean_cpu_efficiency_bps" => stats.mean_cpu_efficiency,
        "mean_cpu_ms_per_gib" => stats.mean_cpu_ms_per_gib,
        "mean_memory_peak_bytes" => stats.mean_memory_peak,
        "mean_bytes_on_wire" => stats.mean_bytes_on_wire,
        "mean_first_usable_output_ms" => stats.mean_first_usable_output.as_secs_f64() * 1000.0,
        "mean_resume_time_ms" => stats.mean_resume_time.as_secs_f64() * 1000.0,
        "mean_disk_amplification_ratio" => stats.mean_disk_amplification_ratio,
        "failure_reproducibility_rate" => stats.failure_reproducibility_rate,
        _ => return None,
    })
}

// Statistical helper functions

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

fn std_dev(values: &[f64]) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }

    let mean_val = mean(values);
    let variance =
        values.iter().map(|x| (x - mean_val).powi(2)).sum::<f64>() / (values.len() - 1) as f64;

    variance.sqrt()
}

fn mean_duration(durations: &[Duration]) -> Duration {
    if durations.is_empty() {
        Duration::ZERO
    } else {
        let total_nanos: u64 = durations.iter().map(|d| d.as_nanos() as u64).sum();
        Duration::from_nanos(total_nanos / durations.len() as u64)
    }
}

fn median_duration(durations: &[Duration]) -> Duration {
    let mut sorted = durations.to_vec();
    sorted.sort();

    let n = sorted.len();
    if n == 0 {
        Duration::ZERO
    } else if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

fn std_dev_duration(durations: &[Duration]) -> Duration {
    if durations.len() <= 1 {
        return Duration::ZERO;
    }

    let mean_nanos = mean_duration(durations).as_nanos() as f64;
    let variance = durations
        .iter()
        .map(|d| (d.as_nanos() as f64 - mean_nanos).powi(2))
        .sum::<f64>()
        / (durations.len() - 1) as f64;

    Duration::from_nanos(variance.sqrt() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_metrics_calculates_throughput() {
        let metrics = BenchmarkMetrics {
            wall_time: Duration::from_secs(2),
            bytes_transferred: 2_000_000,
            verified_completion: true,
            cpu_time: None,
            memory_peak: None,
            bytes_on_wire: None,
            first_usable_output: None,
            resume_time: None,
            disk_amplification_ratio: Some(1.0),
            failure_reproducible: None,
            failure_mode: None,
        };

        let throughput = metrics.throughput_bps().unwrap();
        assert_eq!(throughput, 1_000_000.0); // 1 MB/s
    }

    #[test]
    fn aggregate_stats_handles_empty_iterations() {
        let result = BenchmarkResult {
            tool_name: "test".to_string(),
            iterations: vec![],
            environment: BenchmarkEnvironment::collect().unwrap(),
        };

        let stats = result.aggregate_stats();
        assert_eq!(stats.success_rate, 0.0);
    }

    #[test]
    fn statistical_functions_work() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(mean(&values), 3.0);
        assert_eq!(median(&values), 3.0);
        assert!((std_dev(&values) - 1.58).abs() < 0.1);
    }

    #[test]
    fn public_regression_report_evaluates_thresholds_and_serializes() {
        let environment = BenchmarkEnvironment::collect().unwrap();
        let result = BenchmarkResult {
            tool_name: "atp-clean-lan".to_string(),
            iterations: vec![BenchmarkMetrics {
                wall_time: Duration::from_millis(200),
                cpu_time: Some(Duration::from_millis(4)),
                memory_peak: Some(32 * 1024 * 1024),
                bytes_transferred: 1024 * 1024,
                bytes_on_wire: Some(1024 * 1024),
                verified_completion: true,
                first_usable_output: Some(Duration::from_millis(75)),
                resume_time: Some(Duration::from_millis(120)),
                disk_amplification_ratio: Some(1.0),
                failure_reproducible: None,
                failure_mode: None,
            }],
            environment,
        };
        let mut atp_results = BTreeMap::new();
        atp_results.insert("clean-lan".to_string(), result);
        let report = BenchmarkReport::new(BTreeMap::new(), atp_results, 1024 * 1024, 1);

        let public = report.public_regression_report(
            "smoke",
            &[
                MetricThreshold::required(
                    "first-usable",
                    "mean_first_usable_output_ms",
                    "ms",
                    ThresholdComparison::LessThanOrEqual,
                    100.0,
                ),
                MetricThreshold::required(
                    "disk-amp",
                    "mean_disk_amplification_ratio",
                    "ratio",
                    ThresholdComparison::LessThanOrEqual,
                    1.0,
                ),
                MetricThreshold::required(
                    "cpu",
                    "mean_cpu_ms_per_gib",
                    "ms/GiB",
                    ThresholdComparison::LessThanOrEqual,
                    5000.0,
                ),
            ],
        );

        assert_eq!(
            public.schema_version,
            PUBLIC_REGRESSION_REPORT_SCHEMA_VERSION
        );
        assert_eq!(public.rows.len(), 3);
        assert!(
            public
                .rows
                .iter()
                .all(|row| row.status == BenchmarkGateStatus::Pass)
        );
        assert!(public.human_summary.contains("3 passed"));
        let encoded = serde_json::to_string(&public).expect("public report must serialize");
        assert!(encoded.contains("mean_first_usable_output_ms"));
        assert!(encoded.contains("atp:clean-lan"));
    }

    #[test]
    fn public_regression_report_classifies_skipped_rows() {
        let environment = BenchmarkEnvironment::collect().unwrap();
        let failed_result = BenchmarkResult {
            tool_name: "scp".to_string(),
            iterations: vec![BenchmarkMetrics {
                wall_time: Duration::from_millis(200),
                cpu_time: None,
                memory_peak: None,
                bytes_transferred: 0,
                bytes_on_wire: None,
                verified_completion: false,
                first_usable_output: None,
                resume_time: None,
                disk_amplification_ratio: None,
                failure_reproducible: Some(true),
                failure_mode: Some("tool unavailable".to_string()),
            }],
            environment,
        };
        let mut baseline_results = BTreeMap::new();
        baseline_results.insert("scp".to_string(), failed_result);
        let report = BenchmarkReport::new(baseline_results, BTreeMap::new(), 1024 * 1024, 1);

        let public = report.public_regression_report(
            "skip-smoke",
            &[MetricThreshold::required(
                "success-rate",
                "verified_completion_rate",
                "ratio",
                ThresholdComparison::Equals,
                1.0,
            )],
        );

        assert_eq!(public.rows.len(), 1);
        assert_eq!(public.rows[0].status, BenchmarkGateStatus::Skipped);
        assert_eq!(
            public.rows[0].skip_reason,
            Some(BenchmarkSkipReason::NoSuccessfulIterations)
        );
        assert!(public.human_summary.contains("1 skipped"));
    }
}
