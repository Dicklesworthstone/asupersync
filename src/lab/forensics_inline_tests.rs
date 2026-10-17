    use super::*;

    #[test]
    fn test_forensics_collector_initialization() {
        let config = ForensicsConfig::default();
        let collector = ForensicsCollector::new(config.clone());

        assert_eq!(collector.config.regression_threshold, 20.0);
        assert!(collector.evidence.is_empty());
        assert!(collector.performance_baselines.is_empty());
    }

    #[test]
    fn test_evidence_collection() {
        let mut collector = ForensicsCollector::new(ForensicsConfig::default());
        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        collector.collect_evidence(
            EvidenceCategory::Performance,
            EvidenceSeverity::Info,
            "Test evidence".to_string(),
            context,
            EvidenceData::PerformanceMetrics {
                execution_time: Duration::from_millis(100),
                memory_usage: 1024,
                cpu_cycles: None,
                cache_misses: None,
            },
        );

        assert_eq!(collector.evidence.len(), 1);
        assert_eq!(
            collector.evidence[0].category,
            EvidenceCategory::Performance
        );
    }

    #[test]
    fn test_performance_regression_detection() {
        let mut collector = ForensicsCollector::new(ForensicsConfig {
            regression_threshold: 10.0,
            ..ForensicsConfig::default()
        });

        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        // Establish baseline
        collector
            .analyze_performance_regression(
                "test_benchmark",
                Duration::from_millis(100),
                1024,
                context.clone(),
            )
            .unwrap();

        // No regression should be detected yet
        assert_eq!(collector.evidence.len(), 0);

        // Trigger regression
        let result = collector
            .analyze_performance_regression(
                "test_benchmark",
                Duration::from_millis(150), // 50% increase
                1024,
                context,
            )
            .unwrap();

        assert!(result.is_some());
        let evidence = result.unwrap();
        assert_eq!(evidence.category, EvidenceCategory::Performance);
        assert_eq!(evidence.severity, EvidenceSeverity::Warning);
    }

    #[test]
    fn test_determinism_violation_analysis() {
        let mut collector = ForensicsCollector::new(ForensicsConfig::default());
        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        let evidence = collector.analyze_determinism_violation(
            "expected_state",
            "actual_state",
            "divergence_point",
            context,
        );

        assert_eq!(evidence.category, EvidenceCategory::Determinism);
        assert_eq!(evidence.severity, EvidenceSeverity::Error);
        assert!(evidence.root_cause.is_some());
        assert_eq!(collector.evidence.len(), 1);
    }

    #[test]
    fn test_forensics_report_generation() {
        let mut collector = ForensicsCollector::new(ForensicsConfig::default());
        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        // Add some evidence
        collector.collect_evidence(
            EvidenceCategory::Performance,
            EvidenceSeverity::Critical,
            "Critical performance issue".to_string(),
            context.clone(),
            EvidenceData::PerformanceMetrics {
                execution_time: Duration::from_secs(1),
                memory_usage: 1024 * 1024,
                cpu_cycles: None,
                cache_misses: None,
            },
        );

        collector.analyze_determinism_violation("expected", "actual", "divergence", context);

        let report = collector.generate_report();
        assert_eq!(report.total_evidence, 2);
        assert_eq!(report.critical_evidence, 1);
        assert_eq!(report.error_evidence, 1);
        assert!(
            report
                .category_breakdown
                .contains_key(&EvidenceCategory::Performance)
        );
        assert!(
            report
                .category_breakdown
                .contains_key(&EvidenceCategory::Determinism)
        );
    }
