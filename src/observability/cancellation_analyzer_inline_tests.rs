    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::observability::cancellation_tracer::{CancellationTraceId, CancellationTraceStep};

    fn test_step(entity_id: String, elapsed_since_prev: Duration) -> CancellationTraceStep {
        CancellationTraceStep {
            step_id: 0,
            entity_id,
            entity_type: EntityType::Task,
            cancel_reason: "test".to_string(),
            cancel_kind: "User".to_string(),
            timestamp: SystemTime::UNIX_EPOCH,
            elapsed_since_start: elapsed_since_prev,
            elapsed_since_prev,
            depth: 0,
            parent_entity: None,
            entity_state: "Cancelled".to_string(),
            propagation_completed: true,
        }
    }

    fn test_trace(
        trace_index: usize,
        start_time: SystemTime,
        total_propagation_time: Duration,
        entities_cancelled: u32,
        steps: Vec<CancellationTraceStep>,
        anomalies: Vec<PropagationAnomaly>,
    ) -> CancellationTrace {
        CancellationTrace {
            trace_id: CancellationTraceId::new(),
            root_cancel_reason: format!("test-{trace_index}"),
            root_cancel_kind: "User".to_string(),
            root_entity: "root".to_string(),
            root_entity_type: EntityType::Task,
            start_time,
            steps,
            is_complete: true,
            total_propagation_time: Some(total_propagation_time),
            max_depth: 3,
            entities_cancelled,
            anomalies,
        }
    }

    #[test]
    fn test_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let _analyzer = CancellationAnalyzer::new(config);
        assert!(true); // Just test creation
    }

    #[test]
    fn test_distribution_stats() {
        let analyzer = CancellationAnalyzer::default();
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = analyzer.calculate_distribution_stats(&values);

        assert_eq!(stats.count, 5);
        assert_eq!(stats.mean, 3.0);
        assert_eq!(stats.median, 3.0);
    }

    #[test]
    fn test_insufficient_data_handling() {
        let analyzer = CancellationAnalyzer::default();
        let traces = Vec::new(); // Empty traces
        let analysis = analyzer.analyze_performance(&traces);

        assert_eq!(analysis.traces_analyzed, 0);
        assert!(!analysis.recommendations.is_empty()); // Should have "collect more data" recommendation
    }

    #[test]
    fn test_empty_input_is_insufficient_even_with_zero_min_sample_size() {
        let analyzer = CancellationAnalyzer::new(AnalyzerConfig {
            min_sample_size: 0,
            ..AnalyzerConfig::default()
        });
        let analysis = analyzer.analyze_performance(&[]);

        assert_eq!(analysis.traces_analyzed, 0);
        assert!(
            analysis
                .cleanup_analysis
                .cleanup_efficiency
                .success_rate
                .is_finite()
        );
        assert_eq!(
            analysis.cleanup_analysis.cleanup_efficiency.success_rate,
            0.0
        );
        assert!(!analysis.recommendations.is_empty());
    }

    #[test]
    fn test_bottleneck_threshold_is_fraction_not_percentage_points() {
        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;
        let traces = (0..10)
            .map(|i| {
                test_trace(
                    i,
                    base_time + Duration::from_secs(i as u64),
                    Duration::from_millis(100),
                    2,
                    vec![
                        test_step("minor".to_string(), Duration::from_millis(1)),
                        test_step("major".to_string(), Duration::from_millis(20)),
                    ],
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();

        let bottlenecks = analyzer.identify_bottlenecks(&traces);

        assert_eq!(bottlenecks.len(), 1);
        assert_eq!(bottlenecks[0].entity_id, "major");
        assert!((bottlenecks[0].impact_percentage - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_trend_analysis_uses_sufficient_history() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        // Create traces with improving latency trend (early high, recent low)
        let mut traces = Vec::new();

        // Early traces (higher latency)
        for i in 0..50 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(100 + i * 2),
                5,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(20),
                )],
                Vec::new(),
            ));
        }

        // Recent traces (lower latency)
        for i in 50..100 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(50 + (i - 50) / 2),
                8,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(15),
                )],
                Vec::new(),
            ));
        }

        let trends = analyzer.analyze_trends(&traces);

        // Should detect improving latency and throughput trends
        assert!(
            matches!(trends.latency_trend, TrendDirection::Improving),
            "Expected improving latency trend, got {:?}",
            trends.latency_trend
        );
        assert!(
            matches!(trends.throughput_trend, TrendDirection::Improving),
            "Expected improving throughput trend, got {:?}",
            trends.throughput_trend
        );
        assert!(
            !matches!(trends.latency_trend, TrendDirection::Insufficient),
            "Should not fall back to Insufficient with sufficient history"
        );
    }

    #[test]
    fn test_regression_detection_uses_sufficient_history() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        let mut traces = Vec::new();

        // Baseline traces (good performance)
        for i in 0..30 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(50),
                10,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(15),
                )],
                Vec::new(),
            ));
        }

        // Recent traces with regression (much higher latency + anomalies)
        for i in 30..50 {
            let mut anomalies = Vec::new();
            if i % 3 == 0 {
                anomalies.push(PropagationAnomaly::SlowPropagation {
                    step_id: 0,
                    entity_id: format!("entity-slow-{}", i),
                    elapsed: Duration::from_millis(150),
                    threshold: Duration::from_millis(50),
                });
            }

            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(200),
                8,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(60),
                )],
                anomalies,
            ));
        }

        let regressions = analyzer.detect_regressions(&traces);

        // Should detect latency and potentially throughput/anomaly regressions
        assert!(!regressions.is_empty(), "Should detect regressions");

        let latency_regression = regressions
            .iter()
            .find(|r| r.metric_name == "average_propagation_time");
        assert!(
            latency_regression.is_some(),
            "Should detect latency regression"
        );

        if let Some(reg) = latency_regression {
            assert!(
                reg.regression_magnitude > 0.2,
                "Should detect significant regression"
            );
            assert!(reg.confidence > 0.0, "Should have confidence measure");
        }
    }

    #[test]
    fn test_trend_analysis_stable_case() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        // Create traces with stable performance (no significant change)
        let mut traces = Vec::new();
        for i in 0..100 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(100),
                5,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(20),
                )],
                Vec::new(),
            ));
        }

        let trends = analyzer.analyze_trends(&traces);

        // Should detect stable trends rather than report insufficient data.
        assert!(
            matches!(trends.latency_trend, TrendDirection::Stable),
            "Expected stable latency trend, got {:?}",
            trends.latency_trend
        );
        assert!(
            !matches!(trends.latency_trend, TrendDirection::Insufficient),
            "Should not return Insufficient for sufficient data"
        );
    }

    #[test]
    fn test_no_regression_with_good_performance() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;

        // Create traces with consistently good performance
        let mut traces = Vec::new();
        for i in 0..50 {
            traces.push(test_trace(
                i as usize,
                base_time + Duration::from_secs(i),
                Duration::from_millis(50),
                10,
                vec![test_step(
                    format!("entity-{}", i % 3),
                    Duration::from_millis(15),
                )],
                Vec::new(),
            ));
        }

        let regressions = analyzer.detect_regressions(&traces);

        // Should not detect any regressions with consistent good performance
        assert!(
            regressions.is_empty(),
            "Should not detect regressions with stable good performance"
        );
    }

    #[test]
    fn test_zero_baseline_trends_do_not_divide_by_zero() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let base_time = SystemTime::UNIX_EPOCH;
        let early_traces = vec![
            test_trace(
                0,
                base_time,
                Duration::ZERO,
                0,
                vec![test_step("entity-a".to_string(), Duration::ZERO)],
                Vec::new(),
            ),
            test_trace(
                1,
                base_time + Duration::from_secs(1),
                Duration::ZERO,
                0,
                vec![test_step("entity-b".to_string(), Duration::ZERO)],
                Vec::new(),
            ),
        ];
        let recent_traces = vec![
            test_trace(
                2,
                base_time + Duration::from_secs(2),
                Duration::from_millis(10),
                2,
                vec![test_step("entity-c".to_string(), Duration::from_millis(10))],
                Vec::new(),
            ),
            test_trace(
                3,
                base_time + Duration::from_secs(3),
                Duration::from_millis(20),
                4,
                vec![test_step("entity-d".to_string(), Duration::from_millis(20))],
                Vec::new(),
            ),
        ];

        assert!(matches!(
            analyzer.calculate_latency_trend(&early_traces, &recent_traces),
            TrendDirection::Degrading
        ));
        assert!(matches!(
            analyzer.calculate_throughput_trend(&early_traces, &recent_traces),
            TrendDirection::Improving
        ));
        assert!(matches!(
            analyzer.calculate_stability_trend(&early_traces, &recent_traces),
            TrendDirection::Degrading
        ));
    }

    #[test]
    fn test_zero_baseline_regressions_do_not_divide_by_zero() {
        use std::time::{Duration, SystemTime};

        let analyzer = CancellationAnalyzer::default();
        let detected_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let baseline_traces = vec![test_trace(
            0,
            SystemTime::UNIX_EPOCH,
            Duration::ZERO,
            0,
            vec![test_step("entity-a".to_string(), Duration::ZERO)],
            Vec::new(),
        )];
        let recent_traces = vec![test_trace(
            1,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            Duration::from_millis(25),
            5,
            vec![test_step("entity-b".to_string(), Duration::from_millis(25))],
            Vec::new(),
        )];

        let latency_regression =
            analyzer.detect_latency_regression(&baseline_traces, &recent_traces, detected_at);
        assert!(
            latency_regression.is_some(),
            "positive latency after a zero baseline should register as a regression"
        );
        assert_eq!(
            latency_regression.unwrap().regression_magnitude,
            1.0,
            "zero-baseline regression magnitude should be clamped to a finite sentinel"
        );

        let throughput_regression =
            analyzer.detect_throughput_regression(&baseline_traces, &recent_traces, detected_at);
        assert!(
            throughput_regression.is_none(),
            "zero throughput baseline should not report a throughput drop regression"
        );
    }
