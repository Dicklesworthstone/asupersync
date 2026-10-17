    use super::*;
    use crate::observability::network_truth::NetworkTruthCollector;

    #[test]
    fn test_diagnostic_report_generation() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let report = reporter.generate_report();

        // Should generate a valid report even with no data
        assert!(report.summary.health_score >= 0.0);
        assert!(report.summary.health_score <= 1.0);
        assert_eq!(report.summary.active_paths, 0);
    }

    #[test]
    fn histogram_quantile_clamps_to_top_bucket_for_overflow_observations() {
        use crate::observability::metrics::HistogramSnapshot;

        // boundaries [1,5,10] + implicit +Inf; all 4 observations exceed 10 so
        // they land in the +Inf overflow bucket → counts [0,0,0,4]. Percentiles
        // must clamp to the top finite boundary (10), not vanish to None (which
        // is the worst-latency case where percentiles matter most).
        let overflow = HistogramSnapshot {
            name: "rtt".to_string(),
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            bucket_counts: vec![0, 0, 0, 4],
            count: 4,
            sum: 1000.0,
        };
        assert_eq!(histogram_quantile(&overflow, 0.50), Some(10.0));
        assert_eq!(histogram_quantile(&overflow, 0.95), Some(10.0));
        assert_eq!(histogram_quantile(&overflow, 0.99), Some(10.0));

        // Normal case (observation in a finite bucket) is unchanged.
        let normal = HistogramSnapshot {
            name: "rtt".to_string(),
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            bucket_counts: vec![0, 3, 0, 0],
            count: 3,
            sum: 9.0,
        };
        assert_eq!(histogram_quantile(&normal, 0.50), Some(5.0));
    }

    #[test]
    fn test_summary_generation() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let summary = reporter.generate_summary();

        // Should contain key information
        assert!(summary.contains("Network Status"));
        assert!(summary.contains("health score"));
        assert!(summary.contains("Limiting factor"));
    }

    #[test]
    fn test_json_serialization() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let json = reporter.generate_json_report().unwrap();

        // Should be valid JSON
        let _: NetworkDiagnosticReport = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_pressure_level_classification() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let mut pressure = PressureModel::new();

        // Test low pressure
        pressure.overall = 0.1;
        assert!(matches!(
            reporter.classify_pressure_level(&pressure),
            PressureLevel::Low
        ));

        // Test high pressure
        pressure.overall = 0.8;
        assert!(matches!(
            reporter.classify_pressure_level(&pressure),
            PressureLevel::Critical
        ));
    }

    #[test]
    fn test_limiting_factor_detection() {
        let collector = NetworkTruthCollector::new();
        let reporter = NetworkDiagnosticReporter::new(collector);

        let mut pressure = PressureModel::new();

        // Test network limiting
        pressure.network = 0.8;
        pressure.disk = 0.2;
        pressure.cpu = 0.1;
        pressure.memory = 0.1;

        assert!(matches!(
            reporter.determine_limiting_factor(&pressure),
            LimitingFactor::Network
        ));

        // Test no bottleneck
        pressure.network = 0.1;
        pressure.disk = 0.1;
        pressure.cpu = 0.1;
        pressure.memory = 0.1;

        assert!(matches!(
            reporter.determine_limiting_factor(&pressure),
            LimitingFactor::None
        ));
    }
