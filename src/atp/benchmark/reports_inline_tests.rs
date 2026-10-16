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
