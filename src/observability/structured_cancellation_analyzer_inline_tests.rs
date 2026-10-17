    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{CancelKind, CancelReason};

    #[test]
    fn test_analyzer_creation() {
        let config = StructuredCancellationConfig::default();
        let analyzer = StructuredCancellationAnalyzer::new(config);

        let stats = analyzer.get_real_time_stats();
        assert_eq!(stats.active_traces, 0);
    }

    #[test]
    fn test_trace_lifecycle_integration() {
        let analyzer = StructuredCancellationAnalyzer::default();

        let trace_id = analyzer.start_trace(
            "test-task".to_string(),
            crate::observability::EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        analyzer.record_step(
            trace_id,
            "child-region".to_string(),
            crate::observability::EntityType::Region,
            &CancelReason::user("propagation"),
            CancelKind::User,
            "Closing".to_string(),
            Some("test-task".to_string()),
            true,
        );

        analyzer.complete_trace(trace_id);

        let stats = analyzer.get_tracer_stats();
        assert_eq!(stats.traces_collected, 1);

        let dashboard = analyzer.get_dashboard();
        assert_eq!(dashboard.completed_traces_period, 1);
    }

    #[test]
    fn test_lab_runtime_integration() {
        let config = StructuredCancellationConfig::default();
        let lab_integration = LabRuntimeIntegration::new(config);

        let analysis = lab_integration.run_scenario(|analyzer| {
            let trace_id = analyzer.start_trace(
                "scenario-task".to_string(),
                crate::observability::EntityType::Task,
                &CancelReason::user("scenario"),
                CancelKind::User,
            );
            analyzer.complete_trace(trace_id);
        });

        assert_eq!(analysis.traces_analyzed, 1);
    }

    #[test]
    fn clear_old_alerts_tolerates_oversized_window() {
        let analyzer = StructuredCancellationAnalyzer::default();

        analyzer.clear_old_alerts(Duration::MAX);

        assert_eq!(
            saturating_system_time_sub(std::time::SystemTime::UNIX_EPOCH, Duration::MAX),
            std::time::SystemTime::UNIX_EPOCH
        );
    }
