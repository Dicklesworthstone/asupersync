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
        self.bytes_on_wire.map(|on_wire| {
            self.bytes_transferred as f64 / on_wire as f64
        })
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

        let wall_times: Vec<Duration> = successful_iterations
            .iter()
            .map(|m| m.wall_time)
            .collect();

        let throughputs: Vec<f64> = successful_iterations
            .iter()
            .filter_map(|m| m.throughput_bps())
            .collect();

        AggregateStats {
            success_rate: successful_iterations.len() as f64 / self.iterations.len() as f64,
            mean_wall_time: mean_duration(&wall_times),
            median_wall_time: median_duration(&wall_times),
            std_dev_wall_time: std_dev_duration(&wall_times),
            mean_throughput: mean(&throughputs),
            median_throughput: median(&throughputs),
            std_dev_throughput: std_dev(&throughputs),
            mean_cpu_efficiency: mean(&successful_iterations
                .iter()
                .filter_map(|m| m.cpu_efficiency())
                .collect::<Vec<_>>()),
            mean_memory_peak: successful_iterations
                .iter()
                .filter_map(|m| m.memory_peak)
                .sum::<u64>() as f64 / successful_iterations.len().max(1) as f64,
        }
    }

    /// Check if this result represents a successful benchmark.
    #[must_use]
    pub fn is_successful(&self) -> bool {
        !self.iterations.is_empty() &&
        self.iterations.iter().any(|m| m.verified_completion)
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
    /// Mean peak memory usage in bytes
    pub mean_memory_peak: f64,
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
            mean_memory_peak: 0.0,
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
            .max_by(|a, b| a.throughput.partial_cmp(&b.throughput).unwrap_or(std::cmp::Ordering::Equal));

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
            .max_by(|a, b| a.throughput.partial_cmp(&b.throughput).unwrap_or(std::cmp::Ordering::Equal));

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
                    atp_stats.mean_wall_time.as_secs_f64() / baseline_stats.mean_wall_time.as_secs_f64()
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
        match (best_baseline, best_atp) {
            (Some(baseline), Some(atp)) => {
                let ratio = atp.throughput / baseline.throughput;
                if ratio >= 1.1 {
                    format!("ATP outperforms baseline by {:.1}x", ratio)
                } else if ratio >= 0.9 {
                    "ATP performance is comparable to baseline".to_string()
                } else {
                    format!("ATP underperforms baseline by {:.1}x", 1.0 / ratio)
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
    let variance = values
        .iter()
        .map(|x| (x - mean_val).powi(2))
        .sum::<f64>() / (values.len() - 1) as f64;

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
        .sum::<f64>() / (durations.len() - 1) as f64;

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
}