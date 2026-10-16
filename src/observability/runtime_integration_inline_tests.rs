    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_integration_creation() {
        let config = CancellationTracerConfig::default();
        let integration = CancellationTracerIntegration::new(config);

        let stats = integration.tracer().stats();
        assert_eq!(stats.traces_collected, 0);
    }

    #[test]
    fn test_task_cancel_flow() {
        let config = CancellationTracerConfig::default();
        let integration = CancellationTracerIntegration::new(config);

        let task_id = TaskId::new_for_test(1, 0);
        let cancel_reason = CancelReason::user("test");
        let cancel_kind = CancelKind::User;

        // Initiate cancellation
        integration.on_task_cancel_initiated(task_id, &cancel_reason, cancel_kind, None);

        // Task should be tracked
        let active_traces = integration.active_task_traces();
        assert!(active_traces.contains_key(&task_id));

        // Acknowledge cancellation
        integration.on_task_cancel_acknowledged(task_id, &cancel_reason, cancel_kind);

        // Enter finalizing
        integration.on_task_finalizing(task_id, &cancel_reason, cancel_kind);

        // Complete cancellation
        integration.on_task_cancel_completed(task_id);

        // Task should no longer be tracked
        let active_traces = integration.active_task_traces();
        assert!(!active_traces.contains_key(&task_id));

        // Should have recorded a complete trace
        let stats = integration.tracer().stats();
        assert_eq!(stats.traces_collected, 1);
        assert!(stats.steps_recorded >= 3); // At least 3 steps recorded
    }

    #[test]
    fn test_region_cancel_flow() {
        let config = CancellationTracerConfig::default();
        let integration = CancellationTracerIntegration::new(config);

        let region_id = RegionId::new_for_test(1, 0);
        let cancel_reason = CancelReason::user("region test");
        let cancel_kind = CancelKind::User;

        // Initiate region cancellation
        integration.on_region_cancel_initiated(region_id, &cancel_reason, cancel_kind, None);

        // Region should be tracked
        let active_traces = integration.active_region_traces();
        assert!(active_traces.contains_key(&region_id));

        // Transition through states
        integration.on_region_state_transition(
            region_id,
            RegionState::Open,
            RegionState::Closing,
            Some(&cancel_reason),
            Some(cancel_kind),
        );

        integration.on_region_state_transition(
            region_id,
            RegionState::Closing,
            RegionState::Draining,
            Some(&cancel_reason),
            Some(cancel_kind),
        );

        integration.on_region_state_transition(
            region_id,
            RegionState::Draining,
            RegionState::Finalizing,
            Some(&cancel_reason),
            Some(cancel_kind),
        );

        // Close region
        integration.on_region_closed(region_id);

        // Region should no longer be tracked
        let active_traces = integration.active_region_traces();
        assert!(!active_traces.contains_key(&region_id));

        // Should have recorded a complete trace
        let stats = integration.tracer().stats();
        assert_eq!(stats.traces_collected, 1);
        assert!(stats.steps_recorded >= 3);
    }
