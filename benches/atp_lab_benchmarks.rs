//! ATP Lab Performance Benchmarks
//!
//! Comprehensive benchmark suite for ATP lab components including forensics,
//! replay minimization, trace processing, and benchmark cartel coordination.

use asupersync::error::Result;
use asupersync::lab::benchmark_cartel::{
    BenchmarkCartel, BenchmarkExecutor, BenchmarkMetadata, BenchmarkResult, CartelConfig,
    EnvironmentInfo, ExpectedCharacteristics, PerformanceCharacteristics, StatisticalMeasurements,
};
use asupersync::lab::forensics::{
    EvidenceCategory, EvidenceData, EvidenceSeverity, ExecutionContext, ExecutionPhase,
    ForensicsCollector, ForensicsConfig,
};
use asupersync::lab::replay_minimization::{
    MinimizationConfig, MinimizationStrategy, ReplayValidator, TraceMinimizer,
};
use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{Time, TraceId};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;

fn rust_version() -> String {
    option_env!("RUSTC_VERSION")
        .unwrap_or("unknown")
        .to_string()
}

fn current_time() -> Time {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Time::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

fn benchmark_context(description: &str) -> ExecutionContext {
    ExecutionContext {
        lab_id: "criterion".to_string(),
        scenario_id: description.to_string(),
        task_id: None,
        region_id: None,
        virtual_time: current_time(),
        real_time: SystemTime::now(),
        phase: ExecutionPhase::Execution,
    }
}

fn collect_benchmark_evidence(collector: &mut ForensicsCollector, description: &str) {
    collector.collect_evidence(
        EvidenceCategory::Benchmark,
        EvidenceSeverity::Info,
        description.to_string(),
        benchmark_context(description),
        EvidenceData::PerformanceMetrics {
            execution_time: Duration::ZERO,
            memory_usage: 0,
            cpu_cycles: None,
            cache_misses: None,
        },
    );
}

fn mock_trace(size: usize) -> Vec<TraceEvent> {
    (0..size)
        .map(|i| {
            TraceEvent::new(
                i as u64,
                Time::from_nanos(i as u64),
                TraceEventKind::UserTrace,
                TraceData::None,
            )
        })
        .collect()
}

/// ATP Lab Forensics Benchmark Executor
#[derive(Debug)]
pub struct ForensicsBenchmarkExecutor {
    name: String,
    config: ForensicsConfig,
}

impl ForensicsBenchmarkExecutor {
    pub fn new(name: String, config: ForensicsConfig) -> Self {
        Self { name, config }
    }
}

#[async_trait::async_trait]
impl BenchmarkExecutor for ForensicsBenchmarkExecutor {
    async fn execute(&self, cartel_config: &CartelConfig) -> Result<BenchmarkResult> {
        let start_time = current_time();
        let elapsed_start = Instant::now();
        let mut measurements = Vec::new();

        // Warmup phase
        for _ in 0..cartel_config.warmup_iterations {
            let mut collector = ForensicsCollector::new(self.config.clone());
            collect_benchmark_evidence(&mut collector, "warmup_test");
        }

        // Measurement phase
        for iteration in 0..cartel_config.measurement_iterations {
            let start = Instant::now();

            let mut collector = ForensicsCollector::new(self.config.clone());
            collect_benchmark_evidence(&mut collector, &format!("bench_iteration_{}", iteration));

            let duration = start.elapsed();
            measurements.push(duration.as_nanos() as f64);
        }

        // Compute statistics
        measurements.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let sample_count = measurements.len();
        let mean_ns = measurements.iter().sum::<f64>() / sample_count as f64;

        let variance = measurements
            .iter()
            .map(|x| (x - mean_ns).powi(2))
            .sum::<f64>()
            / sample_count as f64;
        let std_dev_ns = variance.sqrt();
        let cv = std_dev_ns / mean_ns;

        let median_ns = if sample_count % 2 == 0 {
            (measurements[sample_count / 2 - 1] + measurements[sample_count / 2]) / 2.0
        } else {
            measurements[sample_count / 2]
        };

        let p95_index = (sample_count as f64 * 0.95) as usize;
        let p99_index = (sample_count as f64 * 0.99) as usize;
        let p95_ns = measurements[p95_index.min(sample_count - 1)];
        let p99_ns = measurements[p99_index.min(sample_count - 1)];
        let min_ns = measurements[0];
        let max_ns = measurements[sample_count - 1];

        let total_duration = elapsed_start.elapsed();
        let throughput_ops_per_sec =
            sample_count as f64 / total_duration.as_secs_f64().max(f64::EPSILON);

        Ok(BenchmarkResult {
            name: self.name.clone(),
            measurements: StatisticalMeasurements {
                mean_ns,
                std_dev_ns,
                cv,
                median_ns,
                p95_ns,
                p99_ns,
                min_ns,
                max_ns,
                sample_count,
            },
            metadata: BenchmarkMetadata {
                start_time,
                total_duration_ms: total_duration.as_millis() as u64,
                target_iterations: cartel_config.measurement_iterations,
                completed_iterations: sample_count,
                environment: self.get_environment_info(),
                config: cartel_config.clone(),
            },
            characteristics: PerformanceCharacteristics {
                throughput_ops_per_sec,
                allocation_rate_mb_per_sec: 50.0, // Estimated
                cpu_utilization_percent: 75.0,    // Estimated
                cache_miss_ratio: 0.05,           // Estimated
                context_switches_per_sec: 100.0,  // Estimated
                gc_pressure_score: 0.2,           // Estimated
            },
            trace_id: Some(TraceId::from_raw(1)),
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn expected_characteristics(&self) -> ExpectedCharacteristics {
        ExpectedCharacteristics {
            min_throughput: 100.0,   // Minimum forensics collections per second
            max_memory_mb: 500.0,    // Maximum memory usage
            max_cpu_percent: 90.0,   // Maximum CPU utilization
            max_runtime_ms: 10000.0, // Maximum runtime per operation
        }
    }
}

impl ForensicsBenchmarkExecutor {
    fn get_environment_info(&self) -> EnvironmentInfo {
        EnvironmentInfo {
            platform: std::env::consts::OS.to_string(),
            cpu_info: "Unknown CPU".to_string(), // Would use actual CPU detection
            memory_mb: 8192,                     // Would use actual memory detection
            rust_version: rust_version(),
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_string(),
            commit_hash: "unknown".to_string(), // Would use git info
        }
    }
}

/// Replay Minimization Benchmark Executor
#[derive(Debug)]
pub struct ReplayBenchmarkExecutor {
    name: String,
    strategy: MinimizationStrategy,
    trace_size: usize,
}

impl ReplayBenchmarkExecutor {
    pub fn new(name: String, strategy: MinimizationStrategy, trace_size: usize) -> Self {
        Self {
            name,
            strategy,
            trace_size,
        }
    }

    fn create_mock_trace(&self, size: usize) -> Vec<TraceEvent> {
        mock_trace(size)
    }
}

#[async_trait::async_trait]
impl BenchmarkExecutor for ReplayBenchmarkExecutor {
    async fn execute(&self, cartel_config: &CartelConfig) -> Result<BenchmarkResult> {
        let start_time = current_time();
        let elapsed_start = Instant::now();
        let mut measurements = Vec::new();

        // Create mock validator for benchmarking
        struct MockValidator;
        impl ReplayValidator for MockValidator {
            fn validate_replay(&self, _events: &[TraceEvent]) -> Result<bool> {
                Ok(true)
            }
            fn target_description(&self) -> String {
                "Mock validation".to_string()
            }
        }

        let validator = Arc::new(MockValidator);
        let config = MinimizationConfig::default();

        // Warmup phase
        for _ in 0..cartel_config.warmup_iterations {
            let mut minimizer =
                TraceMinimizer::new(config.clone(), validator.clone(), self.strategy);
            let trace = self.create_mock_trace(self.trace_size / 10); // Smaller for warmup
            let _ = minimizer.minimize(trace).await?;
        }

        // Measurement phase
        for _iteration in 0..cartel_config.measurement_iterations {
            let start = Instant::now();

            let mut minimizer =
                TraceMinimizer::new(config.clone(), validator.clone(), self.strategy);
            let trace = self.create_mock_trace(self.trace_size);
            let _result = minimizer.minimize(trace).await?;

            let duration = start.elapsed();
            measurements.push(duration.as_nanos() as f64);
        }

        // Compute statistics (same as forensics benchmark)
        measurements.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let sample_count = measurements.len();
        let mean_ns = measurements.iter().sum::<f64>() / sample_count as f64;

        let variance = measurements
            .iter()
            .map(|x| (x - mean_ns).powi(2))
            .sum::<f64>()
            / sample_count as f64;
        let std_dev_ns = variance.sqrt();
        let cv = std_dev_ns / mean_ns;

        let median_ns = if sample_count % 2 == 0 {
            (measurements[sample_count / 2 - 1] + measurements[sample_count / 2]) / 2.0
        } else {
            measurements[sample_count / 2]
        };

        let p95_index = (sample_count as f64 * 0.95) as usize;
        let p99_index = (sample_count as f64 * 0.99) as usize;
        let p95_ns = measurements[p95_index.min(sample_count - 1)];
        let p99_ns = measurements[p99_index.min(sample_count - 1)];
        let min_ns = measurements[0];
        let max_ns = measurements[sample_count - 1];

        let total_duration = elapsed_start.elapsed();
        let throughput_ops_per_sec =
            sample_count as f64 / total_duration.as_secs_f64().max(f64::EPSILON);

        Ok(BenchmarkResult {
            name: self.name.clone(),
            measurements: StatisticalMeasurements {
                mean_ns,
                std_dev_ns,
                cv,
                median_ns,
                p95_ns,
                p99_ns,
                min_ns,
                max_ns,
                sample_count,
            },
            metadata: BenchmarkMetadata {
                start_time,
                total_duration_ms: total_duration.as_millis() as u64,
                target_iterations: cartel_config.measurement_iterations,
                completed_iterations: sample_count,
                environment: EnvironmentInfo {
                    platform: std::env::consts::OS.to_string(),
                    cpu_info: "Unknown CPU".to_string(),
                    memory_mb: 8192,
                    rust_version: rust_version(),
                    build_profile: if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    }
                    .to_string(),
                    commit_hash: "unknown".to_string(),
                },
                config: cartel_config.clone(),
            },
            characteristics: PerformanceCharacteristics {
                throughput_ops_per_sec,
                allocation_rate_mb_per_sec: 100.0,
                cpu_utilization_percent: 85.0,
                cache_miss_ratio: 0.08,
                context_switches_per_sec: 150.0,
                gc_pressure_score: 0.3,
            },
            trace_id: Some(TraceId::from_raw(2)),
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn expected_characteristics(&self) -> ExpectedCharacteristics {
        ExpectedCharacteristics {
            min_throughput: 10.0,    // Minimum minimizations per second
            max_memory_mb: 1000.0,   // Maximum memory usage
            max_cpu_percent: 95.0,   // Maximum CPU utilization
            max_runtime_ms: 30000.0, // Maximum runtime per operation
        }
    }
}

/// Criterion-based benchmarks for integration with standard Rust benchmark tooling
pub fn forensics_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("ATP Lab Forensics");
    group.throughput(Throughput::Elements(1));

    // Benchmark different forensics configurations
    let configs = vec![
        ("basic", ForensicsConfig::default()),
        (
            "verbose",
            ForensicsConfig {
                enable_performance_tracking: true,
                enable_resource_tracking: true,
                enable_concurrency_analysis: true,
                ..Default::default()
            },
        ),
    ];

    for (name, config) in configs {
        group.bench_with_input(
            BenchmarkId::new("evidence_collection", name),
            &config,
            |b, config| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut collector = ForensicsCollector::new(config.clone());
                        collect_benchmark_evidence(&mut collector, "benchmark_test");
                        collector.generate_report()
                    })
                })
            },
        );
    }

    group.finish();
}

pub fn replay_minimization_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("ATP Lab Replay Minimization");

    // Benchmark different minimization strategies
    let strategies = vec![
        ("delta_debugging", MinimizationStrategy::DeltaDebugging),
        (
            "dependency_pruning",
            MinimizationStrategy::DependencyPruning,
        ),
        ("causal_cone", MinimizationStrategy::CausalCone),
        ("hybrid", MinimizationStrategy::Hybrid),
    ];

    let trace_sizes = vec![100, 1000, 10000];

    for (strategy_name, strategy) in strategies {
        for &trace_size in &trace_sizes {
            group.throughput(Throughput::Elements(trace_size as u64));

            group.bench_with_input(
                BenchmarkId::new(format!("minimize_{}", strategy_name), trace_size),
                &(strategy, trace_size),
                |b, (strategy, trace_size)| {
                    b.iter(|| {
                        rt.block_on(async {
                            // Mock validator
                            struct MockValidator;
                            impl ReplayValidator for MockValidator {
                                fn validate_replay(&self, _events: &[TraceEvent]) -> Result<bool> {
                                    Ok(true)
                                }
                                fn target_description(&self) -> String {
                                    "Mock validation".to_string()
                                }
                            }

                            let validator = Arc::new(MockValidator);
                            let config = MinimizationConfig::default();
                            let mut minimizer = TraceMinimizer::new(config, validator, *strategy);

                            let trace = mock_trace(*trace_size);

                            minimizer.minimize(trace).await.unwrap()
                        })
                    })
                },
            );
        }
    }

    group.finish();
}

pub fn benchmark_cartel_coordination(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("ATP Lab Benchmark Cartel");

    group.bench_function("cartel_execution", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = CartelConfig {
                    concurrency: 2,
                    measurement_iterations: 10,
                    warmup_iterations: 2,
                    ..Default::default()
                };

                let (mut cartel, _events) = BenchmarkCartel::new(config);

                // Register mock executors
                let executor1 = Arc::new(ForensicsBenchmarkExecutor::new(
                    "mock_forensics".to_string(),
                    ForensicsConfig::default(),
                ));

                let executor2 = Arc::new(ReplayBenchmarkExecutor::new(
                    "mock_replay".to_string(),
                    MinimizationStrategy::DeltaDebugging,
                    100,
                ));

                cartel.register_executor(executor1);
                cartel.register_executor(executor2);

                cartel.run_all_benchmarks().await.unwrap()
            })
        })
    });

    group.finish();
}

pub fn comprehensive_atp_lab_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("ATP Lab Comprehensive");

    // End-to-end benchmark combining all components
    group.bench_function("full_lab_pipeline", |b| {
        b.iter(|| {
            rt.block_on(async {
                // 1. Create forensics evidence
                let forensics_config = ForensicsConfig::default();
                let mut collector = ForensicsCollector::new(forensics_config);
                collect_benchmark_evidence(&mut collector, "pipeline_test");

                // 2. Minimize any traces in evidence
                struct MockValidator;
                impl ReplayValidator for MockValidator {
                    fn validate_replay(&self, _events: &[TraceEvent]) -> Result<bool> {
                        Ok(true)
                    }
                    fn target_description(&self) -> String {
                        "Pipeline validation".to_string()
                    }
                }

                let validator = Arc::new(MockValidator);
                let minimization_config = MinimizationConfig::default();
                let mut minimizer = TraceMinimizer::new(
                    minimization_config,
                    validator,
                    MinimizationStrategy::Hybrid,
                );

                // Create mock trace from evidence
                let _minimized = minimizer.minimize(mock_trace(100)).await.unwrap();

                // 3. Run benchmark cartel analysis
                let cartel_config = CartelConfig {
                    measurement_iterations: 5,
                    warmup_iterations: 1,
                    ..Default::default()
                };

                let (mut cartel, _events) = BenchmarkCartel::new(cartel_config);
                let executor = Arc::new(ForensicsBenchmarkExecutor::new(
                    "pipeline_forensics".to_string(),
                    ForensicsConfig::default(),
                ));

                cartel.register_executor(executor);
                let _results = cartel.run_all_benchmarks().await.unwrap();

                collector.generate_report()
            })
        })
    });

    group.finish();
}

// Integration with criterion benchmarking framework
criterion_group!(
    benches,
    forensics_benchmarks,
    replay_minimization_benchmarks,
    benchmark_cartel_coordination,
    comprehensive_atp_lab_benchmarks
);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[tokio::test]
    async fn test_forensics_benchmark_executor() {
        let executor = ForensicsBenchmarkExecutor::new(
            "test_forensics".to_string(),
            ForensicsConfig::default(),
        );

        let config = CartelConfig {
            warmup_iterations: 1,
            measurement_iterations: 5,
            ..Default::default()
        };

        let result = executor.execute(&config).await;
        assert!(result.is_ok());

        let benchmark_result = result.unwrap();
        assert_eq!(benchmark_result.name, "test_forensics");
        assert_eq!(benchmark_result.measurements.sample_count, 5);
        assert!(benchmark_result.measurements.mean_ns > 0.0);
    }

    #[tokio::test]
    async fn test_replay_benchmark_executor() {
        let executor = ReplayBenchmarkExecutor::new(
            "test_replay".to_string(),
            MinimizationStrategy::DeltaDebugging,
            50,
        );

        let config = CartelConfig {
            warmup_iterations: 1,
            measurement_iterations: 3,
            ..Default::default()
        };

        let result = executor.execute(&config).await;
        assert!(result.is_ok());

        let benchmark_result = result.unwrap();
        assert_eq!(benchmark_result.name, "test_replay");
        assert_eq!(benchmark_result.measurements.sample_count, 3);
    }

    #[tokio::test]
    async fn test_cartel_integration() {
        let config = CartelConfig {
            concurrency: 1,
            warmup_iterations: 1,
            measurement_iterations: 2,
            ..Default::default()
        };

        let (mut cartel, mut events) = BenchmarkCartel::new(config);

        let executor = Arc::new(ForensicsBenchmarkExecutor::new(
            "integration_test".to_string(),
            ForensicsConfig::default(),
        ));

        cartel.register_executor(executor);

        // Run benchmarks in background
        let cartel_handle = tokio::spawn(async move { cartel.run_all_benchmarks().await });

        // Collect events
        let mut event_count = 0;
        while let Some(_event) = events.recv().await {
            event_count += 1;
            if event_count >= 2 {
                // Started + Completed
                break;
            }
        }

        let results = cartel_handle.await.unwrap().unwrap();
        assert_eq!(results.len(), 1);
        assert!(event_count >= 2);
    }
}
