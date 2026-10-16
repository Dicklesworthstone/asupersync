    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn test_step(
        step_id: u32,
        entity_id: &str,
        entity_type: EntityType,
        parent_entity: Option<&str>,
        depth: u32,
        elapsed_since_prev: Duration,
        propagation_completed: bool,
    ) -> CancellationTraceStep {
        CancellationTraceStep {
            step_id,
            entity_id: entity_id.to_string(),
            entity_type,
            cancel_reason: "User(test)".to_string(),
            cancel_kind: "User".to_string(),
            timestamp: std::time::SystemTime::UNIX_EPOCH + elapsed_since_prev,
            elapsed_since_start: elapsed_since_prev * (step_id + 1),
            elapsed_since_prev,
            depth,
            parent_entity: parent_entity.map(str::to_string),
            entity_state: "Cancelling".to_string(),
            propagation_completed,
        }
    }

    fn test_trace(steps: Vec<CancellationTraceStep>) -> CancellationTrace {
        let max_depth = steps.iter().map(|step| step.depth).max().unwrap_or(0);
        CancellationTrace {
            trace_id: CancellationTraceId::new(),
            root_cancel_reason: "User(test)".to_string(),
            root_cancel_kind: "User".to_string(),
            root_entity: "root-task".to_string(),
            root_entity_type: EntityType::Task,
            start_time: std::time::SystemTime::UNIX_EPOCH,
            entities_cancelled: steps.len() as u32,
            steps,
            is_complete: true,
            total_propagation_time: Some(Duration::from_millis(50)),
            max_depth,
            anomalies: Vec::new(),
        }
    }

    #[test]
    fn test_visualizer_creation() {
        let config = VisualizerConfig::default();
        let _visualizer = CancellationVisualizer::new(config);

        // Just test that creation works
        assert!(true);
    }

    #[test]
    fn test_duration_formatting() {
        let visualizer = CancellationVisualizer::default();

        let duration = Duration::from_millis(123);
        let formatted = visualizer.format_duration(duration);
        assert!(formatted.contains("123"));
    }

    #[test]
    fn trace_tree_includes_nested_propagation_steps() {
        let visualizer = CancellationVisualizer::default();
        let trace = test_trace(vec![
            test_step(
                0,
                "region-a",
                EntityType::Region,
                Some("root-task"),
                1,
                Duration::from_millis(5),
                true,
            ),
            test_step(
                1,
                "task-b",
                EntityType::Task,
                Some("region-a"),
                2,
                Duration::from_millis(7),
                true,
            ),
        ]);

        let tree = visualizer.build_tree(&trace);

        assert_eq!(tree.entity_id, "root-task");
        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].entity_id, "region-a");
        assert_eq!(tree.children[0].children.len(), 1);
        assert_eq!(tree.children[0].children[0].entity_id, "task-b");

        let rendered = visualizer.visualize_trace_tree(&trace);
        assert!(rendered.contains("region-a"));
        assert!(rendered.contains("task-b"));
    }

    #[test]
    fn trace_tree_preserves_steps_with_missing_parents() {
        let visualizer = CancellationVisualizer::default();
        let trace = test_trace(vec![test_step(
            0,
            "orphan-region",
            EntityType::Region,
            Some("missing-parent"),
            2,
            Duration::from_millis(3),
            false,
        )]);

        let tree = visualizer.build_tree(&trace);

        assert_eq!(tree.children.len(), 1);
        assert_eq!(tree.children[0].entity_id, "orphan-region");
        assert!(!tree.children[0].completed);
    }

    #[test]
    fn anomaly_matching_is_entity_and_step_specific() {
        let visualizer = CancellationVisualizer::default();
        let non_anomalous = test_step(
            0,
            "fast-task",
            EntityType::Task,
            Some("root-task"),
            1,
            Duration::from_millis(200),
            true,
        );
        let anomalous = test_step(
            1,
            "slow-task",
            EntityType::Task,
            Some("root-task"),
            1,
            Duration::from_millis(100),
            true,
        );
        let anomaly = PropagationAnomaly::SlowPropagation {
            step_id: 1,
            entity_id: "slow-task".to_string(),
            elapsed: Duration::from_millis(100),
            threshold: Duration::from_millis(10),
        };

        assert!(!visualizer.step_has_anomaly(&non_anomalous, &anomaly));
        assert!(visualizer.step_has_anomaly(&anomalous, &anomaly));
    }

    #[test]
    fn dashboard_throughput_aggregates_repeated_entities() {
        let visualizer = CancellationVisualizer::default();
        let trace = test_trace(vec![
            test_step(
                0,
                "worker",
                EntityType::Task,
                Some("root-task"),
                1,
                Duration::from_millis(10),
                true,
            ),
            test_step(
                1,
                "worker",
                EntityType::Task,
                Some("root-task"),
                1,
                Duration::from_millis(30),
                false,
            ),
        ]);

        let dashboard = visualizer.generate_dashboard(&[trace]);
        let stats = dashboard
            .entity_throughput
            .get("worker")
            .expect("worker throughput should be aggregated");

        assert_eq!(stats.avg_processing_time, Duration::from_millis(20));
        assert_eq!(stats.success_rate, 0.5);
        assert!(stats.cancellations_per_second > 0.0);
    }

    #[test]
    fn dot_graph_namespaces_traces_and_escapes_labels() {
        let visualizer = CancellationVisualizer::default();
        let mut trace_a = test_trace(vec![test_step(
            0,
            "child\"a",
            EntityType::Task,
            Some("root-task"),
            1,
            Duration::from_millis(1),
            true,
        )]);
        trace_a.root_entity = "root\"task".to_string();
        trace_a.root_cancel_reason = "line\nbreak".to_string();

        let mut trace_b = test_trace(Vec::new());
        trace_b.root_entity = trace_a.root_entity.clone();

        let dot = visualizer.generate_dot_graph(&[trace_a.clone(), trace_b.clone()]);

        assert!(dot.contains(&format!("trace:{}:root\\\"task", trace_a.trace_id.as_u64())));
        assert!(dot.contains(&format!("trace:{}:root\\\"task", trace_b.trace_id.as_u64())));
        assert!(dot.contains("child\\\"a"));
        assert!(dot.contains("line\\nbreak"));
    }

    /// br-asupersync-indxfz — entity_throughput map MUST stay
    /// bounded when traces carry attacker-shaped (high-cardinality)
    /// entity_id strings; excess entities fold into the
    /// `__overflow__` sentinel.
    #[test]
    fn indxfz_entity_throughput_cap_with_overflow_bucket() {
        use std::time::SystemTime;
        let visualizer = CancellationVisualizer::new(VisualizerConfig::default());
        let cap = super::MAX_THROUGHPUT_ENTITIES;
        let total = cap + 50;
        let mut traces = Vec::with_capacity(total);
        for i in 0..total {
            let trace_id = CancellationTraceId::new();
            let step = CancellationTraceStep {
                step_id: 1,
                entity_id: format!("entity_{i}"),
                entity_type: EntityType::Region,
                cancel_reason: "test".to_string(),
                cancel_kind: "User".to_string(),
                timestamp: SystemTime::UNIX_EPOCH,
                elapsed_since_start: Duration::from_micros(10),
                elapsed_since_prev: Duration::from_micros(10),
                depth: 1,
                parent_entity: None,
                entity_state: "closing".to_string(),
                propagation_completed: true,
            };
            traces.push(CancellationTrace {
                trace_id,
                root_cancel_reason: "test".to_string(),
                root_cancel_kind: "User".to_string(),
                root_entity: format!("root_{i}"),
                root_entity_type: EntityType::Region,
                start_time: SystemTime::UNIX_EPOCH,
                steps: vec![step],
                is_complete: true,
                total_propagation_time: Some(Duration::from_micros(10)),
                max_depth: 1,
                entities_cancelled: 1,
                anomalies: Vec::new(),
            });
        }
        let throughput = visualizer.calculate_entity_throughput(&traces);
        assert!(
            throughput.len() <= cap + 1,
            "entity_throughput grew past cap+overflow: {} (cap {cap})",
            throughput.len()
        );
        assert!(
            throughput.contains_key(super::THROUGHPUT_OVERFLOW_BUCKET),
            "overflow sentinel must be present once cap is exceeded"
        );
    }
