//! Benchmark Cartel for ATP Lab Performance Testing
//!
//! Provides a coordinated benchmarking infrastructure for deterministic performance
//! analysis across multiple ATP lab instances. Manages distributed benchmark execution,
//! result collection, and performance regression detection.

use crate::error::{Error, ErrorKind, Result};
use crate::types::{Time, TraceId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{info, warn};

fn current_time() -> Time {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Time::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

/// Configuration for benchmark cartel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartelConfig {
    /// Number of benchmark instances to run concurrently
    pub concurrency: usize,
    /// Warmup iterations before measurement
    pub warmup_iterations: usize,
    /// Measurement iterations for stable results
    pub measurement_iterations: usize,
    /// Timeout for individual benchmarks
    pub benchmark_timeout_ms: u64,
    /// Enable deterministic timing for reproducible results
    pub deterministic_timing: bool,
    /// Minimum runtime for statistical significance
    pub min_runtime_ms: u64,
    /// Maximum coefficient of variation for stability
    pub max_cv_threshold: f64,
    /// Enable performance regression detection
    pub regression_detection: bool,
    /// Baseline performance data directory
    pub baseline_dir: Option<PathBuf>,
}

impl Default for CartelConfig {
    fn default() -> Self {
        Self {
            concurrency: 4,
            warmup_iterations: 10,
            measurement_iterations: 100,
            benchmark_timeout_ms: 30_000,
            deterministic_timing: true,
            min_runtime_ms: 1000,
            max_cv_threshold: 0.05, // 5% coefficient of variation
            regression_detection: true,
            baseline_dir: None,
        }
    }
}

/// Benchmark execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Benchmark name/identifier
    pub name: String,
    /// Statistical measurements
    pub measurements: StatisticalMeasurements,
    /// Runtime metadata
    pub metadata: BenchmarkMetadata,
    /// Performance characteristics
    pub characteristics: PerformanceCharacteristics,
    /// Optional trace information
    pub trace_id: Option<TraceId>,
}

/// Statistical measurements from benchmark execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalMeasurements {
    /// Mean execution time in nanoseconds
    pub mean_ns: f64,
    /// Standard deviation in nanoseconds
    pub std_dev_ns: f64,
    /// Coefficient of variation
    pub cv: f64,
    /// Median execution time
    pub median_ns: f64,
    /// 95th percentile
    pub p95_ns: f64,
    /// 99th percentile
    pub p99_ns: f64,
    /// Minimum observed time
    pub min_ns: f64,
    /// Maximum observed time
    pub max_ns: f64,
    /// Number of samples collected
    pub sample_count: usize,
}

/// Benchmark execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetadata {
    /// Timestamp when benchmark started
    pub start_time: Time,
    /// Total duration including warmup
    pub total_duration_ms: u64,
    /// Target iterations requested
    pub target_iterations: usize,
    /// Actual iterations completed
    pub completed_iterations: usize,
    /// Environment information
    pub environment: EnvironmentInfo,
    /// Configuration used
    pub config: CartelConfig,
}

/// Environment information for reproducibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    /// Platform identifier
    pub platform: String,
    /// CPU model and core count
    pub cpu_info: String,
    /// Available memory
    pub memory_mb: u64,
    /// Rust version used
    pub rust_version: String,
    /// Cargo build profile
    pub build_profile: String,
    /// Git commit hash
    pub commit_hash: String,
}

/// Performance characteristics analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceCharacteristics {
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Memory allocation rate
    pub allocation_rate_mb_per_sec: f64,
    /// CPU utilization percentage
    pub cpu_utilization_percent: f64,
    /// Cache miss ratio
    pub cache_miss_ratio: f64,
    /// Context switch rate
    pub context_switches_per_sec: f64,
    /// GC pressure indicator
    pub gc_pressure_score: f64,
}

/// Benchmark execution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkStrategy {
    /// Single-threaded sequential execution
    Sequential,
    /// Multi-threaded concurrent execution
    Concurrent,
    /// Distributed across multiple instances
    Distributed,
    /// Mixed deterministic workload
    MixedWorkload,
}

/// Performance regression analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionAnalysis {
    /// Whether a regression was detected
    pub regression_detected: bool,
    /// Severity of the regression
    pub severity: RegressionSeverity,
    /// Performance delta compared to baseline
    pub performance_delta_percent: f64,
    /// Statistical significance
    pub p_value: f64,
    /// Confidence interval
    pub confidence_interval: (f64, f64),
    /// Recommendation for action
    pub recommendation: String,
}

/// Regression severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegressionSeverity {
    /// No significant regression
    None,
    /// Minor performance degradation
    Minor,
    /// Moderate performance impact
    Moderate,
    /// Severe performance regression
    Severe,
    /// Critical performance failure
    Critical,
}

/// Abstract trait for benchmark execution
#[async_trait::async_trait]
pub trait BenchmarkExecutor: Send + Sync {
    /// Execute the benchmark with given configuration
    async fn execute(&self, config: &CartelConfig) -> Result<BenchmarkResult>;

    /// Get benchmark name for identification
    fn name(&self) -> &str;

    /// Get expected runtime characteristics
    fn expected_characteristics(&self) -> ExpectedCharacteristics;

    /// Setup benchmark environment if needed
    async fn setup(&self) -> Result<()> {
        Ok(())
    }

    /// Cleanup after benchmark execution
    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}

/// Expected performance characteristics for validation
#[derive(Debug, Clone)]
pub struct ExpectedCharacteristics {
    pub min_throughput: f64,
    pub max_memory_mb: f64,
    pub max_cpu_percent: f64,
    pub max_runtime_ms: f64,
}

/// Benchmark cartel coordinator
pub struct BenchmarkCartel {
    config: CartelConfig,
    executors: Vec<Arc<dyn BenchmarkExecutor>>,
    results_store: Arc<RwLock<HashMap<String, Vec<BenchmarkResult>>>>,
    baseline_store: Arc<RwLock<HashMap<String, BenchmarkResult>>>,
    active_benchmarks: Arc<Mutex<HashMap<String, Instant>>>,
    event_sender: mpsc::UnboundedSender<CartelEvent>,
}

/// Events emitted by the benchmark cartel
#[derive(Debug, Clone)]
pub enum CartelEvent {
    /// Benchmark started
    BenchmarkStarted { name: String, timestamp: Time },
    /// Benchmark completed
    BenchmarkCompleted {
        name: String,
        result: BenchmarkResult,
    },
    /// Benchmark failed
    BenchmarkFailed { name: String, error: String },
    /// Regression detected
    RegressionDetected { analysis: RegressionAnalysis },
    /// Performance improvement detected
    ImprovementDetected {
        name: String,
        improvement_percent: f64,
    },
}

impl BenchmarkCartel {
    /// Create new benchmark cartel
    pub fn new(config: CartelConfig) -> (Self, mpsc::UnboundedReceiver<CartelEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();

        let cartel = Self {
            config,
            executors: Vec::new(),
            results_store: Arc::new(RwLock::new(HashMap::new())),
            baseline_store: Arc::new(RwLock::new(HashMap::new())),
            active_benchmarks: Arc::new(Mutex::new(HashMap::new())),
            event_sender: tx,
        };

        (cartel, rx)
    }

    /// Register a benchmark executor
    pub fn register_executor(&mut self, executor: Arc<dyn BenchmarkExecutor>) {
        info!("Registering benchmark executor: {}", executor.name());
        self.executors.push(executor);
    }

    /// Run all registered benchmarks
    pub async fn run_all_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        info!(
            "Starting benchmark cartel execution with {} executors",
            self.executors.len()
        );

        let mut handles = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));

        for executor in &self.executors {
            let executor = Arc::clone(executor);
            let config = self.config.clone();
            let semaphore = Arc::clone(&semaphore);
            let event_sender = self.event_sender.clone();
            let active_benchmarks = Arc::clone(&self.active_benchmarks);

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let name = executor.name().to_string();

                // Track active benchmark
                {
                    let mut active = active_benchmarks.lock().await;
                    active.insert(name.clone(), Instant::now());
                }

                // Send start event
                let _ = event_sender.send(CartelEvent::BenchmarkStarted {
                    name: name.clone(),
                    timestamp: current_time(),
                });

                // Execute benchmark
                let result = Self::run_single_benchmark(executor, &config).await;

                // Remove from active tracking
                {
                    let mut active = active_benchmarks.lock().await;
                    active.remove(&name);
                }

                // Send completion or failure event
                match &result {
                    Ok(bench_result) => {
                        let _ = event_sender.send(CartelEvent::BenchmarkCompleted {
                            name: name.clone(),
                            result: bench_result.clone(),
                        });
                    }
                    Err(e) => {
                        let _ = event_sender.send(CartelEvent::BenchmarkFailed {
                            name: name.clone(),
                            error: e.to_string(),
                        });
                    }
                }

                result
            });

            handles.push(handle);
        }

        // Wait for all benchmarks to complete
        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => {
                    results.push(result);
                }
                Ok(Err(e)) => {
                    warn!("Benchmark failed: {}", e);
                }
                Err(e) => {
                    warn!("Benchmark task panicked: {}", e);
                }
            }
        }

        // Store results
        self.store_results(&results).await;

        // Check for regressions if enabled
        if self.config.regression_detection {
            self.check_regressions(&results).await?;
        }

        info!(
            "Benchmark cartel execution completed: {} results",
            results.len()
        );
        Ok(results)
    }

    /// Run a single benchmark with timeout
    async fn run_single_benchmark(
        executor: Arc<dyn BenchmarkExecutor>,
        config: &CartelConfig,
    ) -> Result<BenchmarkResult> {
        let timeout = Duration::from_millis(config.benchmark_timeout_ms);

        tokio::time::timeout(timeout, async move {
            executor.setup().await?;
            let result = executor.execute(config).await;
            executor.cleanup().await?;
            result
        })
        .await
        .map_err(|_| Error::new(ErrorKind::DeadlineExceeded).with_message("benchmark timed out"))?
    }

    /// Store benchmark results
    async fn store_results(&self, results: &[BenchmarkResult]) {
        let mut store = self.results_store.write().await;

        for result in results {
            let entry = store.entry(result.name.clone()).or_insert_with(Vec::new);
            entry.push(result.clone());

            // Keep only recent results (last 100)
            if entry.len() > 100 {
                entry.remove(0);
            }
        }
    }

    /// Check for performance regressions
    async fn check_regressions(&self, current_results: &[BenchmarkResult]) -> Result<()> {
        let baseline_store = self.baseline_store.read().await;

        for result in current_results {
            if let Some(baseline) = baseline_store.get(&result.name) {
                let analysis = self.analyze_regression(baseline, result)?;

                if analysis.regression_detected {
                    warn!(
                        "Performance regression detected in {}: {:.1}% slower",
                        result.name, analysis.performance_delta_percent
                    );

                    let _ = self.event_sender.send(CartelEvent::RegressionDetected {
                        analysis: analysis.clone(),
                    });
                } else if analysis.performance_delta_percent < -5.0 {
                    // Significant improvement
                    let _ = self.event_sender.send(CartelEvent::ImprovementDetected {
                        name: result.name.clone(),
                        improvement_percent: -analysis.performance_delta_percent,
                    });
                }
            }
        }

        Ok(())
    }

    /// Analyze performance regression between baseline and current
    fn analyze_regression(
        &self,
        baseline: &BenchmarkResult,
        current: &BenchmarkResult,
    ) -> Result<RegressionAnalysis> {
        let baseline_mean = baseline.measurements.mean_ns;
        let current_mean = current.measurements.mean_ns;

        let delta_percent = ((current_mean - baseline_mean) / baseline_mean) * 100.0;

        // Simple statistical significance test (t-test approximation)
        let pooled_std = (baseline.measurements.std_dev_ns + current.measurements.std_dev_ns) / 2.0;
        let standard_error = pooled_std * (2.0 / baseline.measurements.sample_count as f64).sqrt();
        let t_statistic = (current_mean - baseline_mean) / standard_error;
        let p_value = self.approximate_p_value(t_statistic);

        let regression_detected = delta_percent > 5.0 && p_value < 0.05;
        let severity = self.classify_regression_severity(delta_percent, p_value);

        let confidence_interval = (
            current_mean - 1.96 * standard_error,
            current_mean + 1.96 * standard_error,
        );

        let recommendation = match severity {
            RegressionSeverity::None => "No action needed".to_string(),
            RegressionSeverity::Minor => "Monitor for trend".to_string(),
            RegressionSeverity::Moderate => "Investigate potential causes".to_string(),
            RegressionSeverity::Severe => "Immediate investigation required".to_string(),
            RegressionSeverity::Critical => {
                "Critical performance issue - halt deployments".to_string()
            }
        };

        Ok(RegressionAnalysis {
            regression_detected,
            severity,
            performance_delta_percent: delta_percent,
            p_value,
            confidence_interval,
            recommendation,
        })
    }

    /// Classify regression severity based on delta and significance
    fn classify_regression_severity(&self, delta_percent: f64, p_value: f64) -> RegressionSeverity {
        if p_value > 0.05 || delta_percent <= 5.0 {
            RegressionSeverity::None
        } else if delta_percent <= 10.0 {
            RegressionSeverity::Minor
        } else if delta_percent <= 25.0 {
            RegressionSeverity::Moderate
        } else if delta_percent <= 50.0 {
            RegressionSeverity::Severe
        } else {
            RegressionSeverity::Critical
        }
    }

    /// Approximate p-value for t-statistic (crude approximation)
    fn approximate_p_value(&self, t_statistic: f64) -> f64 {
        let abs_t = t_statistic.abs();

        if abs_t < 1.96 {
            0.05 + (1.96 - abs_t) * 0.45 / 1.96
        } else {
            0.05 * (-abs_t + 1.96).exp()
        }
    }

    /// Get current git commit hash for baseline validation
    fn get_current_commit_hash() -> Result<String> {
        let output = std::process::Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .map_err(|e| Error::internal(format!("failed to get current commit hash: {e}")))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(Error::internal("git rev-parse failed"))
        }
    }

    /// Check if baseline is compatible with current codebase
    fn is_baseline_compatible(baseline: &BenchmarkResult, current_commit: &str) -> (bool, String) {
        let baseline_commit = &baseline.metadata.environment.commit_hash;

        // Exact match is always compatible
        if baseline_commit == current_commit {
            return (true, "Exact commit match".to_string());
        }

        // If baseline commit is empty or unknown, consider it stale
        if baseline_commit.is_empty() || baseline_commit == "unknown" {
            return (
                false,
                "Baseline has no commit hash - likely stale".to_string(),
            );
        }

        // Different commits are potentially incompatible
        // In a production system, you might check if commits are on the same branch
        // or within a certain time window, but for safety we'll warn about any mismatch
        (
            false,
            format!(
                "Commit mismatch: baseline={}, current={}",
                &baseline_commit[..8.min(baseline_commit.len())],
                &current_commit[..8.min(current_commit.len())]
            ),
        )
    }

    /// Load baseline results from storage with validation
    pub async fn load_baselines(&self, baseline_dir: &Path) -> Result<()> {
        if !baseline_dir.exists() {
            warn!(
                "Baseline directory does not exist: {}",
                baseline_dir.display()
            );
            return Ok(());
        }

        // br-asupersync-q92qqo: Get current commit hash for baseline validation
        let current_commit = Self::get_current_commit_hash().unwrap_or_else(|e| {
            warn!("Failed to get current commit hash: {}", e);
            "unknown".to_string()
        });

        let mut baseline_store = self.baseline_store.write().await;
        let mut loaded_count = 0;
        let mut skipped_count = 0;
        let mut stale_baselines = Vec::new();

        let mut entries = tokio::fs::read_dir(baseline_dir).await.map_err(|e| {
            Error::internal(format!(
                "failed to read baseline directory {}: {e}",
                baseline_dir.display()
            ))
        })?;
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            Error::internal(format!(
                "failed to iterate baseline directory {}: {e}",
                baseline_dir.display()
            ))
        })? {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(result) = serde_json::from_str::<BenchmarkResult>(&content) {
                        // br-asupersync-q92qqo: Validate baseline compatibility
                        let (compatible, reason) =
                            Self::is_baseline_compatible(&result, &current_commit);

                        if compatible {
                            baseline_store.insert(result.name.clone(), result);
                            loaded_count += 1;
                        } else {
                            warn!(
                                "Skipping incompatible baseline '{}': {}",
                                result.name, reason
                            );
                            stale_baselines.push((result.name.clone(), reason));
                            skipped_count += 1;
                        }
                    } else {
                        warn!("Failed to parse baseline file: {}", path.display());
                    }
                } else {
                    warn!("Failed to read baseline file: {}", path.display());
                }
            }
        }

        info!(
            "Loaded {} compatible baseline results, skipped {} incompatible baselines",
            loaded_count, skipped_count
        );

        if !stale_baselines.is_empty() {
            warn!(
                "Found {} stale baselines that may cause false regression alerts or miss real regressions:",
                stale_baselines.len()
            );
            for (name, reason) in stale_baselines {
                warn!("  - {}: {}", name, reason);
            }
            warn!(
                "Consider regenerating baselines for current commit to ensure reliable CI/CD benchmarks"
            );
        }

        Ok(())
    }

    /// Save current results as new baselines
    pub async fn save_baselines(&self, baseline_dir: &Path) -> Result<()> {
        tokio::fs::create_dir_all(baseline_dir).await.map_err(|e| {
            Error::internal(format!(
                "failed to create baseline directory {}: {e}",
                baseline_dir.display()
            ))
        })?;

        let results_store = self.results_store.read().await;

        for (name, results) in results_store.iter() {
            if let Some(latest) = results.last() {
                let filename = format!("{}.json", name.replace('/', "_"));
                let path = baseline_dir.join(filename);

                let content = serde_json::to_string_pretty(latest).map_err(|e| {
                    Error::internal(format!(
                        "failed to serialize benchmark baseline {name}: {e}"
                    ))
                })?;
                tokio::fs::write(&path, content).await.map_err(|e| {
                    Error::internal(format!(
                        "failed to write benchmark baseline {}: {e}",
                        path.display()
                    ))
                })?;
            }
        }

        info!("Saved baselines to {}", baseline_dir.display());
        Ok(())
    }

    /// Get current benchmark results
    pub async fn get_results(&self, benchmark_name: &str) -> Option<Vec<BenchmarkResult>> {
        let store = self.results_store.read().await;
        store.get(benchmark_name).cloned()
    }

    /// Get active benchmark status
    pub async fn get_active_benchmarks(&self) -> HashMap<String, Duration> {
        let active = self.active_benchmarks.lock().await;
        let now = Instant::now();

        active
            .iter()
            .map(|(name, start_time)| (name.clone(), now.duration_since(*start_time)))
            .collect()
    }
}

/// Utility functions for benchmark analysis
pub mod analysis {
    use super::*;

    /// Compare two sets of benchmark results
    pub fn compare_result_sets(
        baseline: &[BenchmarkResult],
        current: &[BenchmarkResult],
    ) -> HashMap<String, f64> {
        let mut comparisons = HashMap::new();

        let baseline_map: HashMap<String, &BenchmarkResult> =
            baseline.iter().map(|r| (r.name.clone(), r)).collect();

        for current_result in current {
            if let Some(baseline_result) = baseline_map.get(&current_result.name) {
                let delta = ((current_result.measurements.mean_ns
                    - baseline_result.measurements.mean_ns)
                    / baseline_result.measurements.mean_ns)
                    * 100.0;
                comparisons.insert(current_result.name.clone(), delta);
            }
        }

        comparisons
    }

    /// Generate performance report
    pub fn generate_performance_report(results: &[BenchmarkResult]) -> String {
        let mut report = String::new();
        report.push_str("# Performance Benchmark Report\n\n");

        for result in results {
            report.push_str(&format!(
                "## {}\n\n\
                - **Mean**: {:.2}ms\n\
                - **Median**: {:.2}ms\n\
                - **P95**: {:.2}ms\n\
                - **P99**: {:.2}ms\n\
                - **CV**: {:.1}%\n\
                - **Throughput**: {:.0} ops/sec\n\n",
                result.name,
                result.measurements.mean_ns / 1_000_000.0,
                result.measurements.median_ns / 1_000_000.0,
                result.measurements.p95_ns / 1_000_000.0,
                result.measurements.p99_ns / 1_000_000.0,
                result.measurements.cv * 100.0,
                result.characteristics.throughput_ops_per_sec
            ));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBenchmarkExecutor {
        name: String,
        mean_ns: f64,
    }

    #[async_trait::async_trait]
    impl BenchmarkExecutor for MockBenchmarkExecutor {
        async fn execute(&self, _config: &CartelConfig) -> Result<BenchmarkResult> {
            Ok(BenchmarkResult {
                name: self.name.clone(),
                measurements: StatisticalMeasurements {
                    mean_ns: self.mean_ns,
                    std_dev_ns: self.mean_ns * 0.1,
                    cv: 0.1,
                    median_ns: self.mean_ns,
                    p95_ns: self.mean_ns * 1.2,
                    p99_ns: self.mean_ns * 1.5,
                    min_ns: self.mean_ns * 0.8,
                    max_ns: self.mean_ns * 1.8,
                    sample_count: 100,
                },
                metadata: BenchmarkMetadata {
                    start_time: current_time(),
                    total_duration_ms: 1000,
                    target_iterations: 100,
                    completed_iterations: 100,
                    environment: EnvironmentInfo {
                        platform: "test".to_string(),
                        cpu_info: "test-cpu".to_string(),
                        memory_mb: 1024,
                        rust_version: "1.70.0".to_string(),
                        build_profile: "release".to_string(),
                        commit_hash: "abc123".to_string(),
                    },
                    config: CartelConfig::default(),
                },
                characteristics: PerformanceCharacteristics {
                    throughput_ops_per_sec: 1_000_000.0 / self.mean_ns * 1_000_000_000.0,
                    allocation_rate_mb_per_sec: 10.0,
                    cpu_utilization_percent: 50.0,
                    cache_miss_ratio: 0.05,
                    context_switches_per_sec: 100.0,
                    gc_pressure_score: 0.1,
                },
                trace_id: None,
            })
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn expected_characteristics(&self) -> ExpectedCharacteristics {
            ExpectedCharacteristics {
                min_throughput: 1000.0,
                max_memory_mb: 100.0,
                max_cpu_percent: 80.0,
                max_runtime_ms: 5000.0,
            }
        }
    }

    #[tokio::test]
    async fn test_benchmark_cartel_creation() {
        let config = CartelConfig::default();
        let (cartel, _rx) = BenchmarkCartel::new(config);

        assert_eq!(cartel.executors.len(), 0);
    }

    #[tokio::test]
    async fn test_benchmark_executor_registration() {
        let config = CartelConfig::default();
        let (mut cartel, _rx) = BenchmarkCartel::new(config);

        let executor = Arc::new(MockBenchmarkExecutor {
            name: "test_benchmark".to_string(),
            mean_ns: 1_000_000.0,
        });

        cartel.register_executor(executor);
        assert_eq!(cartel.executors.len(), 1);
    }

    #[tokio::test]
    async fn test_regression_analysis() {
        let config = CartelConfig::default();
        let (cartel, _rx) = BenchmarkCartel::new(config);

        let baseline = BenchmarkResult {
            name: "test".to_string(),
            measurements: StatisticalMeasurements {
                mean_ns: 1_000_000.0,
                std_dev_ns: 100_000.0,
                cv: 0.1,
                median_ns: 1_000_000.0,
                p95_ns: 1_200_000.0,
                p99_ns: 1_500_000.0,
                min_ns: 800_000.0,
                max_ns: 1_800_000.0,
                sample_count: 100,
            },
            metadata: BenchmarkMetadata {
                start_time: current_time(),
                total_duration_ms: 1000,
                target_iterations: 100,
                completed_iterations: 100,
                environment: EnvironmentInfo {
                    platform: "test".to_string(),
                    cpu_info: "test-cpu".to_string(),
                    memory_mb: 1024,
                    rust_version: "1.70.0".to_string(),
                    build_profile: "release".to_string(),
                    commit_hash: "abc123".to_string(),
                },
                config: CartelConfig::default(),
            },
            characteristics: PerformanceCharacteristics {
                throughput_ops_per_sec: 1000.0,
                allocation_rate_mb_per_sec: 10.0,
                cpu_utilization_percent: 50.0,
                cache_miss_ratio: 0.05,
                context_switches_per_sec: 100.0,
                gc_pressure_score: 0.1,
            },
            trace_id: None,
        };

        let mut current = baseline.clone();
        current.measurements.mean_ns = 1_200_000.0; // 20% slower

        let analysis = cartel.analyze_regression(&baseline, &current).unwrap();
        assert!(analysis.regression_detected);
        assert_eq!(analysis.severity, RegressionSeverity::Moderate);
    }

    #[test]
    fn test_baseline_compatibility_validation() {
        let create_baseline = |commit_hash: &str| BenchmarkResult {
            name: "test".to_string(),
            measurements: StatisticalMeasurements {
                mean_ns: 1_000_000.0,
                std_dev_ns: 100_000.0,
                cv: 0.1,
                median_ns: 1_000_000.0,
                p95_ns: 1_200_000.0,
                p99_ns: 1_500_000.0,
                min_ns: 800_000.0,
                max_ns: 1_800_000.0,
                sample_count: 100,
            },
            metadata: BenchmarkMetadata {
                start_time: current_time(),
                total_duration_ms: 1000,
                target_iterations: 100,
                completed_iterations: 100,
                environment: EnvironmentInfo {
                    platform: "test".to_string(),
                    cpu_info: "test-cpu".to_string(),
                    memory_mb: 1024,
                    rust_version: "1.70.0".to_string(),
                    build_profile: "release".to_string(),
                    commit_hash: commit_hash.to_string(),
                },
                config: CartelConfig::default(),
            },
            characteristics: PerformanceCharacteristics {
                throughput_ops_per_sec: 1000.0,
                allocation_rate_mb_per_sec: 10.0,
                cpu_utilization_percent: 50.0,
                cache_miss_ratio: 0.05,
                context_switches_per_sec: 100.0,
                gc_pressure_score: 0.1,
            },
            trace_id: None,
        };

        let current_commit = "abc123def456";

        // Test exact commit match - should be compatible
        let same_commit_baseline = create_baseline(current_commit);
        let (compatible, reason) =
            BenchmarkCartel::is_baseline_compatible(&same_commit_baseline, current_commit);
        assert!(compatible);
        assert_eq!(reason, "Exact commit match");

        // Test different commit - should be incompatible
        let different_commit_baseline = create_baseline("xyz789uvw012");
        let (compatible, reason) =
            BenchmarkCartel::is_baseline_compatible(&different_commit_baseline, current_commit);
        assert!(!compatible);
        assert!(reason.contains("Commit mismatch"));

        // Test empty commit hash - should be incompatible
        let empty_commit_baseline = create_baseline("");
        let (compatible, reason) =
            BenchmarkCartel::is_baseline_compatible(&empty_commit_baseline, current_commit);
        assert!(!compatible);
        assert!(reason.contains("no commit hash"));

        // Test "unknown" commit hash - should be incompatible
        let unknown_commit_baseline = create_baseline("unknown");
        let (compatible, reason) =
            BenchmarkCartel::is_baseline_compatible(&unknown_commit_baseline, current_commit);
        assert!(!compatible);
        assert!(reason.contains("no commit hash"));
    }
}
