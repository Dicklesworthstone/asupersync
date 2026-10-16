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
    fn test_tracer_creation() {
        let config = CancellationTracerConfig::default();
        let tracer = CancellationTracer::new(config);
        let stats = tracer.stats();
        assert_eq!(stats.traces_collected, 0);
        assert_eq!(stats.steps_recorded, 0);
    }

    #[test]
    fn zero_sample_rate_rejects_zero_hash_boundary() {
        let mut config = CancellationTracerConfig::default();
        config.sample_rate = 0.0;
        let tracer = CancellationTracer::new(config);

        assert_eq!(tracer.sample_unit_interval(0), 0.0);
        assert!(
            !tracer.should_sample_hash(0),
            "sample_rate=0.0 must reject even the exact zero-hash boundary"
        );

        let trace_id = tracer.start_trace(
            "task-zero-rate".to_string(),
            EntityType::Task,
            &CancelReason::user("sampling-disabled"),
            CancelKind::User,
        );
        tracer.record_step(
            trace_id,
            "region-zero-rate".to_string(),
            EntityType::Region,
            &CancelReason::user("should-not-record"),
            CancelKind::User,
            "Closing".to_string(),
            Some("task-zero-rate".to_string()),
            true,
        );
        tracer.complete_trace(trace_id);

        let stats = tracer.stats();
        assert_eq!(stats.traces_collected, 0);
        assert_eq!(stats.steps_recorded, 0);
        assert!(tracer.completed_traces().is_empty());
        assert!(tracer.in_progress_traces().is_empty());
        assert!(tracer.traces_for_entity("task-zero-rate").is_empty());
    }

    #[test]
    fn non_finite_sample_rate_rejects_sampling() {
        let mut config = CancellationTracerConfig::default();
        config.sample_rate = f64::NAN;
        let tracer = CancellationTracer::new(config);

        assert!(
            !tracer.should_sample_hash(0),
            "non-finite sample rates must fail closed"
        );
        assert!(
            !tracer.should_sample_hash(u64::MAX),
            "non-finite sample rates must not sample any hash boundary"
        );
    }

    #[test]
    fn test_trace_lifecycle() {
        let config = CancellationTracerConfig::default();
        let tracer = CancellationTracer::new(config);

        // Start a trace
        let trace_id = tracer.start_trace(
            "task-1".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        // Record a step
        tracer.record_step(
            trace_id,
            "region-1".to_string(),
            EntityType::Region,
            &CancelReason::user("propagation"),
            CancelKind::User,
            "Closing".to_string(),
            Some("task-1".to_string()),
            true,
        );

        // Complete the trace
        tracer.complete_trace(trace_id);

        let stats = tracer.stats();
        assert_eq!(stats.traces_collected, 1);
        assert_eq!(stats.steps_recorded, 1);

        let completed = tracer.completed_traces();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].is_complete);
    }

    #[test]
    fn test_anomaly_detection() {
        let mut config = CancellationTracerConfig::default();
        config.slow_propagation_threshold_ms = 1; // Very low threshold for testing
        let tracer = CancellationTracer::new(config);

        let trace_id = tracer.start_trace(
            "task-1".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        // Simulate slow propagation by adding delay
        std::thread::sleep(Duration::from_millis(5));

        tracer.record_step(
            trace_id,
            "region-1".to_string(),
            EntityType::Region,
            &CancelReason::user("slow"),
            CancelKind::User,
            "Closing".to_string(),
            Some("task-1".to_string()),
            true,
        );

        tracer.complete_trace(trace_id);

        let completed = tracer.completed_traces();
        assert!(!completed.is_empty());

        // Should detect slow propagation anomaly
        assert!(!completed[0].anomalies.is_empty());
        assert!(matches!(
            completed[0].anomalies[0],
            PropagationAnomaly::SlowPropagation { .. }
        ));
    }

    #[test]
    fn test_anomaly_counter_counts_only_new_anomalies() {
        let mut config = CancellationTracerConfig::default();
        config.max_trace_depth = 0;
        let tracer = CancellationTracer::new(config);

        let trace_id = tracer.start_trace(
            "root-task".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        tracer.record_step(
            trace_id,
            "child-task".to_string(),
            EntityType::Task,
            &CancelReason::user("too deep"),
            CancelKind::User,
            "Cancelling".to_string(),
            Some("root-task".to_string()),
            true,
        );
        tracer.record_step(
            trace_id,
            "root-task".to_string(),
            EntityType::Task,
            &CancelReason::user("root observed"),
            CancelKind::User,
            "Cancelling".to_string(),
            None,
            true,
        );

        tracer.complete_trace(trace_id);

        let stats = tracer.stats();
        assert_eq!(stats.anomalies_detected, 1);

        let completed = tracer.completed_traces();
        assert_eq!(completed[0].anomalies.len(), 1);
        assert!(matches!(
            completed[0].anomalies[0],
            PropagationAnomaly::ExcessiveDepth { .. }
        ));
    }

    #[test]
    fn test_child_before_parent_ordering_detected_when_parent_arrives() {
        let tracer = CancellationTracer::new(CancellationTracerConfig::default());

        let trace_id = tracer.start_trace(
            "root-task".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        tracer.record_step(
            trace_id,
            "child-task".to_string(),
            EntityType::Task,
            &CancelReason::user("child first"),
            CancelKind::User,
            "Cancelling".to_string(),
            Some("parent-region".to_string()),
            true,
        );
        tracer.record_step(
            trace_id,
            "parent-region".to_string(),
            EntityType::Region,
            &CancelReason::user("parent late"),
            CancelKind::User,
            "Cancelling".to_string(),
            Some("root-task".to_string()),
            true,
        );

        tracer.complete_trace(trace_id);

        let completed = tracer.completed_traces();
        assert!(completed[0].anomalies.iter().any(|anomaly| matches!(
            anomaly,
            PropagationAnomaly::IncorrectPropagationOrder {
                parent_entity,
                child_entity,
                parent_step: 1,
                child_step: 0,
            } if parent_entity == "parent-region" && child_entity == "child-task"
        )));
        assert_eq!(tracer.stats().incorrect_orders, 1);
    }

    #[test]
    fn test_stuck_cancellation_threshold_detects_incomplete_step() {
        let mut config = CancellationTracerConfig::default();
        config.stuck_cancellation_timeout_ms = 0;
        let tracer = CancellationTracer::new(config);

        let trace_id = tracer.start_trace(
            "root-task".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        tracer.record_step(
            trace_id,
            "child-task".to_string(),
            EntityType::Task,
            &CancelReason::user("not done"),
            CancelKind::User,
            "Cancelling".to_string(),
            Some("root-task".to_string()),
            false,
        );

        tracer.complete_trace(trace_id);

        let completed = tracer.completed_traces();
        assert!(completed[0].anomalies.iter().any(|anomaly| matches!(
            anomaly,
            PropagationAnomaly::StuckCancellation { entity_id, .. }
                if entity_id == "child-task"
        )));
        assert_eq!(tracer.stats().stuck_cancellations, 1);
    }

    #[test]
    fn test_completed_latest_state_is_not_reported_as_stuck() {
        let mut config = CancellationTracerConfig::default();
        config.stuck_cancellation_timeout_ms = 0;
        let tracer = CancellationTracer::new(config);

        let trace_id = tracer.start_trace(
            "root-task".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        tracer.record_step(
            trace_id,
            "child-task".to_string(),
            EntityType::Task,
            &CancelReason::user("requested"),
            CancelKind::User,
            "Cancelling".to_string(),
            Some("root-task".to_string()),
            false,
        );
        tracer.record_step(
            trace_id,
            "child-task".to_string(),
            EntityType::Task,
            &CancelReason::user("completed"),
            CancelKind::User,
            "Cancelled".to_string(),
            None,
            true,
        );

        tracer.complete_trace(trace_id);

        let completed = tracer.completed_traces();
        assert!(!completed[0].anomalies.iter().any(|anomaly| matches!(
            anomaly,
            PropagationAnomaly::StuckCancellation { entity_id, .. }
                if entity_id == "child-task"
        )));
        assert_eq!(tracer.stats().stuck_cancellations, 0);
    }

    #[test]
    fn test_missing_parent_is_reported_when_trace_completes() {
        let tracer = CancellationTracer::new(CancellationTracerConfig::default());

        let trace_id = tracer.start_trace(
            "root-task".to_string(),
            EntityType::Task,
            &CancelReason::user("test"),
            CancelKind::User,
        );

        tracer.record_step(
            trace_id,
            "child-task".to_string(),
            EntityType::Task,
            &CancelReason::user("orphan child"),
            CancelKind::User,
            "Cancelling".to_string(),
            Some("missing-parent".to_string()),
            true,
        );

        tracer.complete_trace(trace_id);

        let completed = tracer.completed_traces();
        assert!(completed[0].anomalies.iter().any(|anomaly| matches!(
            anomaly,
            PropagationAnomaly::UnexpectedPropagation {
                description,
                affected_entities,
            } if description.contains("missing-parent")
                && affected_entities == &vec![
                    "missing-parent".to_string(),
                    "child-task".to_string()
                ]
        )));
    }

    #[test]
    fn test_analysis_patterns() {
        let traces = vec![
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "test1".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "task-1".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(10)),
                max_depth: 3,
                entities_cancelled: 5,
                anomalies: vec![],
            },
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "test2".to_string(),
                root_cancel_kind: "Timeout".to_string(),
                root_entity: "task-2".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(5)),
                max_depth: 2,
                entities_cancelled: 3,
                anomalies: vec![],
            },
        ];

        let analysis = analyze_cancellation_patterns(&traces);
        assert_eq!(analysis.traces_analyzed, 2);
        assert_eq!(analysis.avg_depth, 2.5);
        assert!(!analysis.common_cancel_kinds.is_empty());
    }

    #[test]
    fn test_analysis_average_ignores_incomplete_traces() {
        let traces = vec![
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "complete".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "task-1".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(10)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![],
            },
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "incomplete".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "task-2".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![],
                is_complete: false,
                total_propagation_time: None,
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![],
            },
        ];

        let analysis = analyze_cancellation_patterns(&traces);

        assert_eq!(analysis.avg_propagation_time, Duration::from_millis(10));
        assert_eq!(analysis.analysis_period, Duration::from_millis(10));
    }

    #[test]
    fn test_bottleneck_detection() {
        // Create traces with various bottleneck patterns
        let traces = vec![
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "bottleneck-entity".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![CancellationTraceStep {
                    step_id: 0,
                    entity_id: "bottleneck-entity".to_string(),
                    entity_type: EntityType::Task,
                    cancel_reason: "high frequency".to_string(),
                    cancel_kind: "User".to_string(),
                    parent_entity: None,
                    timestamp: crate::observability::replayable_system_time(),
                    elapsed_since_start: Duration::from_millis(1),
                    elapsed_since_prev: Duration::from_millis(1),
                    depth: 0,
                    entity_state: "Cancelled".to_string(),
                    propagation_completed: true,
                }],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(1)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![
                    PropagationAnomaly::SlowPropagation {
                        step_id: 0,
                        entity_id: "slow-entity".to_string(),
                        elapsed: Duration::from_millis(100),
                        threshold: Duration::from_millis(1),
                    },
                    PropagationAnomaly::StuckCancellation {
                        entity_id: "stuck-entity".to_string(),
                        stuck_duration: Duration::from_millis(500),
                    },
                ],
            },
            // Create multiple traces to make "bottleneck-entity" high frequency
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "bottleneck-entity".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![CancellationTraceStep {
                    step_id: 0,
                    entity_id: "bottleneck-entity".to_string(),
                    entity_type: EntityType::Task,
                    cancel_reason: "high frequency".to_string(),
                    cancel_kind: "User".to_string(),
                    parent_entity: None,
                    timestamp: crate::observability::replayable_system_time(),
                    elapsed_since_start: Duration::from_millis(1),
                    elapsed_since_prev: Duration::from_millis(1),
                    depth: 0,
                    entity_state: "Cancelled".to_string(),
                    propagation_completed: true,
                }],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(1)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![],
            },
            CancellationTrace {
                trace_id: CancellationTraceId::new(),
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: "other-entity".to_string(),
                root_entity_type: EntityType::Task,
                start_time: crate::observability::replayable_system_time(),
                steps: vec![CancellationTraceStep {
                    step_id: 0,
                    entity_id: "other-entity".to_string(),
                    entity_type: EntityType::Task,
                    cancel_reason: "normal".to_string(),
                    cancel_kind: "User".to_string(),
                    parent_entity: None,
                    timestamp: crate::observability::replayable_system_time(),
                    elapsed_since_start: Duration::from_millis(1),
                    elapsed_since_prev: Duration::from_millis(1),
                    depth: 0,
                    entity_state: "Cancelled".to_string(),
                    propagation_completed: true,
                }],
                is_complete: true,
                total_propagation_time: Some(Duration::from_millis(1)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: vec![],
            },
        ];

        let analysis = analyze_cancellation_patterns(&traces);

        // Should detect bottlenecks
        assert!(
            !analysis.bottlenecks.is_empty(),
            "Should detect bottlenecks"
        );

        // Check for high-frequency bottleneck (bottleneck-entity appears in 2/3 traces)
        let has_high_freq_bottleneck = analysis.bottlenecks.iter().any(|b| {
            b.contains("High-frequency cancellation source") && b.contains("bottleneck-entity")
        });
        assert!(
            has_high_freq_bottleneck,
            "Should detect high-frequency cancellation source"
        );

        // Check for slow propagation bottleneck
        let has_slow_bottleneck = analysis
            .bottlenecks
            .iter()
            .any(|b| b.contains("Slow propagation bottleneck") && b.contains("slow-entity"));
        assert!(
            has_slow_bottleneck,
            "Should detect slow propagation bottleneck"
        );

        // Check for stuck cancellation bottleneck
        let has_stuck_bottleneck = analysis
            .bottlenecks
            .iter()
            .any(|b| b.contains("Stuck cancellation bottleneck") && b.contains("stuck-entity"));
        assert!(
            has_stuck_bottleneck,
            "Should detect stuck cancellation bottleneck"
        );

        // Should include recommendation about addressing bottlenecks
        let has_bottleneck_recommendation = analysis
            .recommendations
            .iter()
            .any(|r| r.contains("Address") && r.contains("bottlenecks"));
        assert!(
            has_bottleneck_recommendation,
            "Should recommend addressing bottlenecks"
        );
    }

    /// br-asupersync-uae0hk — entity_traces map MUST stay bounded
    /// when a producer feeds attacker-shaped (high-cardinality)
    /// entity_id strings. Excess entities fold into the
    /// `__overflow__` bucket and per-entity trace lists are
    /// FIFO-trimmed to MAX_TRACES_PER_ENTITY.
    #[test]
    fn uae0hk_entity_traces_cap_with_overflow_bucket() {
        let tracer = CancellationTracer::new(CancellationTracerConfig::default());
        // Inject MAX_TRACED_ENTITIES + 100 distinct entities. With
        // MAX_TRACED_ENTITIES = 4096 and a real start_trace per
        // call this would be slow; instead we exercise the gate
        // directly via the public start_trace API for a
        // representative subset and assert the cap on the inner map.
        let cap = super::MAX_TRACED_ENTITIES;
        let reason = CancelReason::user("uae0hk-cap-test");
        for i in 0..cap + 50 {
            let _ = tracer.start_trace(
                format!("entity_{i}"),
                EntityType::Region,
                &reason,
                CancelKind::User,
            );
        }
        let entity_traces = tracer.entity_traces.lock().expect("lock");
        assert!(
            entity_traces.len() <= cap + 1,
            "entity_traces grew past cap+overflow: {} (cap {cap})",
            entity_traces.len()
        );
        assert!(
            entity_traces.contains_key(super::ENTITY_OVERFLOW_BUCKET),
            "overflow sentinel must be present once cap is exceeded"
        );
    }
