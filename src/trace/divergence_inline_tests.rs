    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::replay::TraceMetadata;
    use crate::trace::{CompactRegionId, CompactTaskId};

    fn make_trace(seed: u64, events: Vec<ReplayEvent>) -> ReplayTrace {
        ReplayTrace {
            metadata: TraceMetadata::new(seed),
            events,
            cursor: 0,
        }
    }

    fn make_error(index: usize, expected: ReplayEvent, actual: ReplayEvent) -> DivergenceError {
        DivergenceError {
            index,
            expected: Some(expected),
            actual,
            context: String::new(),
        }
    }

    fn scrub_divergence_text(text: &str) -> String {
        text.replace("Seed:       0x000000000000beef", "Seed:       [SEED]")
    }

    // -------------------------------------------------------------------------
    // Classification tests
    // -------------------------------------------------------------------------

    #[test]
    fn classify_scheduling_order() {
        let cat = classify_divergence(
            Some(&ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            }),
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );
        assert_eq!(cat, DivergenceCategory::SchedulingOrder);
    }

    #[test]
    fn classify_outcome_mismatch() {
        let cat = classify_divergence(
            Some(&ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            }),
            &ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 2,
            },
        );
        assert_eq!(cat, DivergenceCategory::OutcomeMismatch);
    }

    #[test]
    fn classify_event_type_mismatch() {
        let cat = classify_divergence(
            Some(&ReplayEvent::RngSeed { seed: 42 }),
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        );
        assert_eq!(cat, DivergenceCategory::EventTypeMismatch);
    }

    #[test]
    fn classify_time_divergence() {
        let cat = classify_divergence(
            Some(&ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 1000,
            }),
            &ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 2000,
            },
        );
        assert_eq!(cat, DivergenceCategory::TimeDivergence);
    }

    #[test]
    fn classify_rng_mismatch() {
        let cat = classify_divergence(
            Some(&ReplayEvent::RngSeed { seed: 42 }),
            &ReplayEvent::RngSeed { seed: 99 },
        );
        assert_eq!(cat, DivergenceCategory::RngMismatch);
    }

    #[test]
    fn classify_checkpoint_mismatch() {
        let cat = classify_divergence(
            Some(&ReplayEvent::Checkpoint {
                sequence: 1,
                time_nanos: 100,
                active_tasks: 3,
                active_regions: 1,
            }),
            &ReplayEvent::Checkpoint {
                sequence: 1,
                time_nanos: 100,
                active_tasks: 5,
                active_regions: 1,
            },
        );
        assert_eq!(cat, DivergenceCategory::CheckpointMismatch);
    }

    // -------------------------------------------------------------------------
    // Full report tests
    // -------------------------------------------------------------------------

    #[test]
    fn diagnose_scheduling_divergence() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(1),
                region: CompactRegionId(100),
                at_tick: 0,
            },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(2),
                region: CompactRegionId(100),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 2,
            },
        ];
        let trace = make_trace(0xDEAD, events);

        let error = make_error(
            3,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::SchedulingOrder);
        assert_eq!(report.divergence_index, 3);
        assert_eq!(report.trace_length, 5);
        assert_eq!(report.minimal_prefix_len, 4);
        assert_eq!(report.seed, 0xDEAD);
        assert!(report.replay_progress_pct > 50.0);
        assert!(report.affected.tasks.contains(&1));
        assert!(report.affected.tasks.contains(&2));
        assert!(report.explanation.contains("Scheduler chose"));
        assert!(!report.context_before.is_empty());
    }

    #[test]
    fn diagnose_outcome_divergence() {
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 3,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::OutcomeMismatch);
        assert!(report.explanation.contains("Panicked"));
        assert!(report.explanation.contains("Ok"));
    }

    #[test]
    fn diagnose_event_type_mismatch() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TimerFired { timer_id: 99 },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::EventTypeMismatch);
        assert!(report.explanation.contains("TaskScheduled"));
        assert!(report.explanation.contains("TimerFired"));
    }

    #[test]
    fn diagnose_trace_exhausted_divergence() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let trace = make_trace(0xCAFE, events);
        let error = DivergenceError {
            index: 1,
            expected: None,
            actual: ReplayEvent::RngSeed { seed: 99 },
            context: "Trace ended but execution continued".to_string(),
        };

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.category, DivergenceCategory::LengthMismatch);
        assert_eq!(report.expected.event_type, "TraceExhausted");
        assert!(
            report
                .expected
                .details
                .contains("recorded trace ended before this event")
        );
        assert!(report.explanation.contains("trace is exhausted"));
        assert_eq!(report.actual.event_type, "RngSeed");
    }

    #[test]
    fn replay_trace_diagnostics_suppress_foata_equivalent_reordering() {
        let expected = make_trace(
            0xFEED,
            vec![
                ReplayEvent::TaskScheduled {
                    task: CompactTaskId(1),
                    at_tick: 0,
                },
                ReplayEvent::TaskScheduled {
                    task: CompactTaskId(2),
                    at_tick: 0,
                },
            ],
        );
        let actual = make_trace(
            0xFEED,
            vec![
                ReplayEvent::TaskScheduled {
                    task: CompactTaskId(2),
                    at_tick: 0,
                },
                ReplayEvent::TaskScheduled {
                    task: CompactTaskId(1),
                    at_tick: 0,
                },
            ],
        );

        assert!(replay_traces_foata_equivalent(&expected, &actual));
        assert!(
            diagnose_replay_trace_divergence(&expected, &actual, &DiagnosticConfig::default())
                .is_none()
        );
    }

    #[test]
    fn replay_trace_diagnostics_report_actual_after_context() {
        let expected = make_trace(
            0xABCD,
            vec![
                ReplayEvent::RngValue { value: 10 },
                ReplayEvent::RngValue { value: 11 },
                ReplayEvent::RngValue { value: 12 },
                ReplayEvent::RngValue { value: 13 },
            ],
        );
        let actual = make_trace(
            0xABCD,
            vec![
                ReplayEvent::RngValue { value: 10 },
                ReplayEvent::RngValue { value: 99 },
                ReplayEvent::RngValue { value: 100 },
                ReplayEvent::RngValue { value: 101 },
            ],
        );
        let config = DiagnosticConfig {
            context_before: 1,
            context_after: 2,
            ..DiagnosticConfig::default()
        };

        let report = diagnose_replay_trace_divergence(&expected, &actual, &config)
            .expect("rng drift should produce divergence");

        assert_eq!(report.category, DivergenceCategory::RngMismatch);
        assert_eq!(report.divergence_index, 1);
        assert_eq!(report.context_after.len(), 2);
        assert_eq!(report.context_after_actual.len(), 2);
        assert!(report.context_after[0].details.contains("000000000000000c"));
        assert!(
            report.context_after_actual[0]
                .details
                .contains("0000000000000064")
        );
        assert!(report.to_text().contains("--- Context (actual after) ---"));
        assert!(
            report
                .to_json()
                .expect("serialize")
                .contains("context_after_actual")
        );
    }

    // -------------------------------------------------------------------------
    // Context window tests
    // -------------------------------------------------------------------------

    #[test]
    fn context_window_bounds() {
        let events: Vec<_> = (0..20)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let error = make_error(
            10,
            ReplayEvent::RngValue { value: 10 },
            ReplayEvent::RngValue { value: 99 },
        );

        let config = DiagnosticConfig {
            context_before: 3,
            context_after: 2,
            ..DiagnosticConfig::default()
        };

        let report = diagnose_divergence(&trace, &error, &config);

        assert_eq!(report.context_before.len(), 3);
        assert_eq!(report.context_after.len(), 2);
        assert_eq!(report.context_before[0].index, 7);
        assert_eq!(report.context_before[2].index, 9);
        assert_eq!(report.context_after[0].index, 11);
    }

    #[test]
    fn context_window_at_start() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 43 },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            0,
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 99 },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert!(report.context_before.is_empty());
        assert_eq!(report.context_after.len(), 1);
    }

    #[test]
    fn context_window_at_end() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 43 },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::RngSeed { seed: 43 },
            ReplayEvent::RngSeed { seed: 99 },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());

        assert_eq!(report.context_before.len(), 1);
        assert!(report.context_after.is_empty());
    }

    // -------------------------------------------------------------------------
    // Minimal prefix tests
    // -------------------------------------------------------------------------

    #[test]
    fn minimal_prefix_extraction() {
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let prefix = minimal_divergent_prefix(&trace, 5);
        assert_eq!(prefix.events.len(), 6); // 0..=5
        assert_eq!(prefix.metadata.seed, 42);
    }

    #[test]
    fn minimal_prefix_at_zero() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let trace = make_trace(42, events);

        let prefix = minimal_divergent_prefix(&trace, 0);
        assert_eq!(prefix.events.len(), 1);
    }

    #[test]
    fn minimal_prefix_beyond_trace() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let trace = make_trace(42, events);

        let prefix = minimal_divergent_prefix(&trace, 100);
        assert_eq!(prefix.events.len(), 1); // clamped to trace length
    }

    // -------------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------------

    #[test]
    fn report_serializes_to_json() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];
        let trace = make_trace(42, events);

        let error = make_error(
            1,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
        let json = report.to_json().expect("serialize");

        // Verify JSON is valid and contains key fields
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["category"], "SchedulingOrder");
        assert_eq!(parsed["divergence_index"], 1);
        assert_eq!(parsed["seed"], 42);
    }

    #[test]
    fn report_renders_text() {
        let events = vec![ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        }];
        let trace = make_trace(0xBEEF, events);

        let error = make_error(
            0,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
        let text = report.to_text();

        assert!(text.contains("Replay Divergence Report"));
        assert!(text.contains("scheduling-order"));
        assert!(text.contains("0x000000000000beef"));
        assert!(text.contains("DIVERGENCE"));
    }

    // -------------------------------------------------------------------------
    // Entity extraction tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_task_entities() {
        let affected = extract_affected_entities(
            Some(&ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            }),
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 0,
            },
        );

        assert_eq!(affected.tasks, vec![1, 2]);
        assert!(affected.regions.is_empty());
        assert!(affected.scheduler_lane.is_some());
    }

    #[test]
    fn extract_region_entities() {
        let affected = extract_affected_entities(
            Some(&ReplayEvent::RegionCreated {
                region: CompactRegionId(10),
                parent: Some(CompactRegionId(5)),
                at_tick: 0,
            }),
            &ReplayEvent::RegionCreated {
                region: CompactRegionId(10),
                parent: None,
                at_tick: 0,
            },
        );

        assert!(affected.tasks.is_empty());
        assert!(affected.regions.contains(&10));
        assert!(affected.regions.contains(&5));
    }

    #[test]
    fn extract_timer_entities() {
        let affected = extract_affected_entities(
            Some(&ReplayEvent::TimerFired { timer_id: 42 }),
            &ReplayEvent::TimerFired { timer_id: 99 },
        );

        assert!(affected.tasks.is_empty());
        assert_eq!(affected.timers, vec![42, 99]);
    }

    // -------------------------------------------------------------------------
    // Event summary tests
    // -------------------------------------------------------------------------

    #[test]
    fn event_summary_from_task_scheduled() {
        let summary = EventSummary::from_event(
            5,
            &ReplayEvent::TaskScheduled {
                task: CompactTaskId(42),
                at_tick: 10,
            },
        );

        assert_eq!(summary.index, 5);
        assert_eq!(summary.event_type, "TaskScheduled");
        assert!(summary.details.contains("tick=10"));
        assert_eq!(summary.task_id, Some(42));
        assert_eq!(summary.region_id, None);
    }

    #[test]
    fn event_summary_from_region_created() {
        let summary = EventSummary::from_event(
            0,
            &ReplayEvent::RegionCreated {
                region: CompactRegionId(7),
                parent: None,
                at_tick: 0,
            },
        );

        assert_eq!(summary.event_type, "RegionCreated");
        assert_eq!(summary.region_id, Some(7));
        assert_eq!(summary.task_id, None);
    }

    // -------------------------------------------------------------------------
    // Prefix minimization tests (bd-2fywr)
    // -------------------------------------------------------------------------

    #[test]
    fn minimize_finds_exact_threshold() {
        // 10 events. Failure reproduces when prefix length >= 6.
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let threshold = 6;
        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |prefix| {
            prefix.len() >= threshold
        });

        assert_eq!(result.minimized_len, threshold);
        assert_eq!(result.original_len, 10);
        assert_eq!(result.prefix.events.len(), threshold);
        assert!(!result.truncated);
    }

    #[test]
    fn minimize_already_minimal() {
        // Single event — already minimal.
        let trace = make_trace(42, vec![ReplayEvent::RngSeed { seed: 42 }]);

        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |_| true);

        assert_eq!(result.minimized_len, 1);
        assert_eq!(result.evaluations, 0);
        assert!(!result.truncated);
    }

    #[test]
    fn minimize_full_prefix_required() {
        // Only the full prefix (length 10) reproduces.
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |prefix| {
            prefix.len() >= 10
        });

        assert_eq!(result.minimized_len, 10);
        assert!(!result.truncated);
    }

    #[test]
    fn minimize_respects_min_prefix_len() {
        // Failure reproduces at length >= 3, but min is 5.
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let config = MinimizationConfig {
            min_prefix_len: 5,
            max_evaluations: 0,
        };

        let result = minimize_divergent_prefix(&trace, &config, |prefix| prefix.len() >= 3);

        // Search starts at min_prefix_len=5, and oracle is true at 5,
        // so result is 5.
        assert_eq!(result.minimized_len, 5);
    }

    #[test]
    fn minimize_respects_max_evaluations() {
        // 1000 events, threshold at 500. With max_evaluations=2,
        // we can't binary-search all the way.
        let events: Vec<_> = (0..1000)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let config = MinimizationConfig {
            min_prefix_len: 1,
            max_evaluations: 2,
        };

        let result = minimize_divergent_prefix(&trace, &config, |prefix| prefix.len() >= 500);

        assert!(result.truncated);
        assert_eq!(result.evaluations, 2);
        // Should still have found a shorter prefix than original.
        assert!(result.minimized_len <= 1000);
        // And it should be a reproducing prefix (>= 500).
        assert!(result.minimized_len >= 500);
    }

    #[test]
    fn minimize_preserves_metadata() {
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(0xBEEF, events);

        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |prefix| {
            prefix.len() >= 5
        });

        assert_eq!(result.prefix.metadata.seed, 0xBEEF);
    }

    #[test]
    fn minimize_binary_search_efficiency() {
        // 1024 events. Binary search should take at most ceil(log2(1024)) = 10 evals.
        let events: Vec<_> = (0..1024)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |prefix| {
            prefix.len() >= 300
        });

        assert_eq!(result.minimized_len, 300);
        assert!(
            result.evaluations <= 10,
            "evaluations={}",
            result.evaluations
        );
    }

    #[test]
    fn minimize_threshold_one() {
        // Any non-empty prefix reproduces.
        let events: Vec<_> = (0..100)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();
        let trace = make_trace(42, events);

        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |_| true);

        assert_eq!(result.minimized_len, 1);
    }

    // =========================================================================
    // Wave 59 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn diagnostic_config_debug_clone() {
        let cfg = DiagnosticConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("DiagnosticConfig"), "{dbg}");
        let cloned = cfg;
        assert_eq!(cloned.context_before, 10);
    }

    #[test]
    fn affected_entities_debug_clone_default() {
        let ae = AffectedEntities::default();
        let dbg = format!("{ae:?}");
        assert!(dbg.contains("AffectedEntities"), "{dbg}");
        let cloned = ae;
        assert!(cloned.tasks.is_empty());
    }

    #[test]
    fn divergence_report_text_snapshot_scrubbed() {
        let trace = make_trace(
            0xBEEF,
            vec![
                ReplayEvent::TaskScheduled {
                    task: CompactTaskId(1),
                    at_tick: 0,
                },
                ReplayEvent::TaskScheduled {
                    task: CompactTaskId(2),
                    at_tick: 1,
                },
                ReplayEvent::TaskCompleted {
                    task: CompactTaskId(2),
                    outcome: 0,
                },
            ],
        );

        let error = make_error(
            1,
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(3),
                at_tick: 1,
            },
        );

        let report = diagnose_divergence(&trace, &error, &DiagnosticConfig::default());
        insta::assert_snapshot!(
            "divergence_report_text_scrubbed",
            scrub_divergence_text(&report.to_text())
        );
    }
