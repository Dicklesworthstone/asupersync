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
