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

    fn make_trace(events: Vec<ReplayEvent>) -> ReplayTrace {
        ReplayTrace {
            metadata: TraceMetadata::new(42),
            events,
            cursor: 0,
        }
    }

    #[test]
    fn basic_replay() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        assert_eq!(replayer.event_count(), 3);
        assert_eq!(replayer.current_index(), 0);
        assert!(!replayer.is_completed());

        // Advance through events
        let e1 = replayer.next().cloned();
        assert!(matches!(e1, Some(ReplayEvent::RngSeed { seed: 42 })));

        let e2 = replayer.next().cloned();
        assert!(matches!(e2, Some(ReplayEvent::TaskScheduled { .. })));

        let e3 = replayer.next().cloned();
        assert!(matches!(e3, Some(ReplayEvent::TaskCompleted { .. })));

        assert!(replayer.is_completed());
        assert!(replayer.next().is_none());
    }

    #[test]
    fn step_mode() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::Step);

        // Each step should stop
        replayer.step().unwrap();
        assert!(replayer.at_breakpoint());

        replayer.step().unwrap();
        assert!(replayer.at_breakpoint());
        assert!(replayer.is_completed());
    }

    #[test]
    fn breakpoint_at_tick() {
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 5,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(3),
                at_tick: 10,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(5)));

        // Run should stop at tick 5
        let count = replayer.run().unwrap();
        assert_eq!(count, 2);
        assert!(replayer.at_breakpoint());
        assert!(!replayer.is_completed());
    }

    #[test]
    fn breakpoint_at_event_index() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::EventIndex(1)));

        // Run should stop at event index 1
        let count = replayer.run().unwrap();
        assert_eq!(count, 2); // Processed events 0 and 1
        assert!(replayer.at_breakpoint());
    }

    #[test]
    fn verify_matching_events() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let replayer = TraceReplayer::new(make_trace(events));

        // Matching event should succeed
        let actual = ReplayEvent::RngSeed { seed: 42 };
        assert!(replayer.verify(&actual).is_ok());
    }

    #[test]
    fn verify_mismatching_events() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let replayer = TraceReplayer::new(make_trace(events));

        // Different event should fail
        let actual = ReplayEvent::RngSeed { seed: 99 };
        let err = replayer.verify(&actual).unwrap_err();
        assert_eq!(err.index, 0);
    }

    #[test]
    fn seek_and_reset() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        // Advance partway
        replayer.next();
        replayer.next();
        assert_eq!(replayer.current_index(), 2);

        // Seek to beginning
        replayer.seek(0).unwrap();
        assert_eq!(replayer.current_index(), 0);
        assert!(!replayer.is_completed());

        // Advance to end
        replayer.next();
        replayer.next();
        replayer.next();
        assert!(replayer.is_completed());

        // Reset
        replayer.reset();
        assert_eq!(replayer.current_index(), 0);
        assert!(!replayer.is_completed());
    }

    #[test]
    fn verify_and_advance() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        // Verify and advance with matching events
        let actual1 = ReplayEvent::RngSeed { seed: 42 };
        assert!(replayer.verify_and_advance(&actual1).is_ok());
        assert_eq!(replayer.current_index(), 1);

        let actual2 = ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        };
        assert!(replayer.verify_and_advance(&actual2).is_ok());
        assert!(replayer.is_completed());
    }

    #[test]
    fn divergence_error_formatting() {
        let expected = ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        };
        let actual = ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 0,
        };

        let err = DivergenceError {
            index: 5,
            expected: Some(expected.clone()),
            actual: actual.clone(),
            context: divergence_context(&expected, &actual),
        };

        let msg = format!("{err}");
        assert!(msg.starts_with("[ASUP-E401]"));
        assert!(msg.contains("event 5"));
        assert!(msg.contains("Different task scheduled"));
    }

    #[test]
    fn divergence_error_formatting_handles_trace_exhausted() {
        let err = DivergenceError {
            index: 7,
            expected: None,
            actual: ReplayEvent::RngSeed { seed: 99 },
            context: "Trace ended but execution continued".to_string(),
        };

        let msg = format!("{err}");
        assert!(msg.starts_with("[ASUP-E401]"));
        assert!(msg.contains("<trace_exhausted>"));
        assert!(msg.contains("event 7"));
    }

    #[test]
    fn remaining_events() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));

        assert_eq!(replayer.remaining_events().len(), 3);

        replayer.next();
        assert_eq!(replayer.remaining_events().len(), 2);

        replayer.next();
        replayer.next();
        assert_eq!(replayer.remaining_events().len(), 0);
    }

    #[test]
    fn breakpoint_at_task() {
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 1,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(3),
                at_tick: 2,
            },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Task(CompactTaskId(2))));

        let count = replayer.run().unwrap();
        assert_eq!(count, 2);
        assert!(replayer.at_breakpoint());
        assert!(!replayer.is_completed());
    }

    #[test]
    fn seek_out_of_bounds_returns_error() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let mut replayer = TraceReplayer::new(make_trace(events));

        let err = replayer.seek(5).unwrap_err();
        assert!(matches!(err, ReplayError::UnexpectedEnd { index: 5 }));
    }

    #[test]
    fn seek_to_end_positions_cursor_at_eof() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 1 },
            ReplayEvent::RngSeed { seed: 2 },
        ];
        let mut replayer = TraceReplayer::new(make_trace(events));

        replayer.seek(replayer.event_count()).unwrap();

        assert_eq!(replayer.current_index(), 2);
        assert!(replayer.is_completed());
        assert!(replayer.peek().is_none());
        assert!(replayer.remaining_events().is_empty());
        assert!(replayer.next().is_none());
    }

    #[test]
    fn seek_to_end_is_valid_for_empty_trace() {
        let mut replayer = TraceReplayer::new(make_trace(vec![]));

        replayer.seek(0).unwrap();

        assert_eq!(replayer.current_index(), 0);
        assert!(replayer.is_completed());
        assert!(replayer.peek().is_none());
        assert!(replayer.remaining_events().is_empty());
        assert_eq!(replayer.run().unwrap(), 0);
    }

    #[test]
    fn verify_past_end_of_trace() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let mut replayer = TraceReplayer::new(make_trace(events));

        // Consume the only event
        replayer.next();
        assert!(replayer.is_completed());

        // Verify past end should produce divergence
        let actual = ReplayEvent::RngSeed { seed: 99 };
        let err = replayer.verify(&actual).unwrap_err();
        assert!(err.expected.is_none());
        assert_eq!(err.index, 1);
        assert!(err.context.contains("Trace ended"));
        assert!(format!("{err}").contains("<trace_exhausted>"));
    }

    #[test]
    fn run_mode_completes_all_events() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 1 },
            ReplayEvent::RngSeed { seed: 2 },
            ReplayEvent::RngSeed { seed: 3 },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::Run);

        let count = replayer.run().unwrap();
        assert_eq!(count, 3);
        assert!(replayer.is_completed());
    }

    #[test]
    fn empty_trace_properties() {
        let mut replayer = TraceReplayer::new(make_trace(vec![]));

        assert_eq!(replayer.event_count(), 0);
        assert!(replayer.remaining_events().is_empty());
        assert!(replayer.peek().is_none());
        assert_eq!(replayer.run().unwrap(), 0);
        assert!(replayer.is_completed());
    }

    #[test]
    fn set_mode_clears_breakpoint_flag() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 1 },
            ReplayEvent::RngSeed { seed: 2 },
        ];

        let mut replayer = TraceReplayer::new(make_trace(events));
        replayer.set_mode(ReplayMode::Step);

        replayer.step().unwrap();
        assert!(replayer.at_breakpoint());

        // Changing mode clears the breakpoint flag
        replayer.set_mode(ReplayMode::Run);
        assert!(!replayer.at_breakpoint());
    }

    #[test]
    fn into_trace_returns_original() {
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        let trace = make_trace(events.clone());
        let seed = trace.metadata.seed;

        let replayer = TraceReplayer::new(trace);
        let recovered = replayer.into_trace();

        assert_eq!(recovered.metadata.seed, seed);
        assert_eq!(recovered.events, events);
    }

    #[test]
    fn metadata_accessible_from_replayer() {
        let events = vec![ReplayEvent::RngSeed { seed: 99 }];
        let trace = make_trace(events);
        let replayer = TraceReplayer::new(trace);

        assert_eq!(replayer.metadata().seed, 42);
        assert_eq!(
            replayer.metadata().version,
            crate::trace::replay::REPLAY_SCHEMA_VERSION
        );
    }

    #[test]
    fn event_source_trait_cursor_advances() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 1 },
            ReplayEvent::RngSeed { seed: 2 },
            ReplayEvent::RngSeed { seed: 3 },
        ];
        let mut trace = make_trace(events);

        let e1 = trace.next_event().expect("event 1");
        assert!(matches!(e1, ReplayEvent::RngSeed { seed: 1 }));

        let e2 = trace.next_event().expect("event 2");
        assert!(matches!(e2, ReplayEvent::RngSeed { seed: 2 }));

        let e3 = trace.next_event().expect("event 3");
        assert!(matches!(e3, ReplayEvent::RngSeed { seed: 3 }));

        assert!(trace.next_event().is_none());
    }

    #[test]
    fn divergence_context_time_advanced() {
        let expected = ReplayEvent::TimeAdvanced {
            from_nanos: 0,
            to_nanos: 1000,
        };
        let actual = ReplayEvent::TimeAdvanced {
            from_nanos: 0,
            to_nanos: 2000,
        };

        let ctx = divergence_context(&expected, &actual);
        assert!(ctx.contains("Time advanced differently"));
    }

    #[test]
    fn divergence_context_task_completed_same_task() {
        let expected = ReplayEvent::TaskCompleted {
            task: CompactTaskId(1),
            outcome: 0,
        };
        let actual = ReplayEvent::TaskCompleted {
            task: CompactTaskId(1),
            outcome: 2,
        };

        let ctx = divergence_context(&expected, &actual);
        assert!(ctx.contains("Different outcome"));
    }

    #[test]
    fn divergence_context_different_variant_types() {
        let expected = ReplayEvent::RngSeed { seed: 1 };
        let actual = ReplayEvent::RngValue { value: 2 };

        // events_match checks discriminant first
        assert!(!events_match(&expected, &actual));
    }

    #[test]
    fn peek_does_not_advance() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RngSeed { seed: 99 },
        ];
        let replayer = TraceReplayer::new(make_trace(events));

        let e1 = replayer.peek().cloned();
        let e2 = replayer.peek().cloned();
        assert_eq!(e1, e2);
        assert_eq!(replayer.current_index(), 0);
    }

    // =========================================================================
    // Wave 59 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn replay_mode_debug_clone_eq_default() {
        let mode = ReplayMode::default();
        let dbg = format!("{mode:?}");
        assert!(dbg.contains("Run"), "{dbg}");
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
        assert_ne!(mode, ReplayMode::Step);
    }

    #[test]
    fn breakpoint_debug_clone_eq() {
        let bp = Breakpoint::Tick(42);
        let dbg = format!("{bp:?}");
        assert!(dbg.contains("Tick"), "{dbg}");
        let cloned = bp.clone();
        assert_eq!(bp, cloned);
        assert_ne!(bp, Breakpoint::EventIndex(7));
    }

    #[test]
    fn browser_replay_report_without_divergence_records_completion() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];
        let mut replayer = TraceReplayer::new(make_trace(events.clone()));
        for event in &events {
            replayer.verify_and_advance(event).expect("self-consistent");
        }

        let report = replayer.browser_replay_report(
            "trace-browser-ok",
            Some("artifacts/replay/browser-ok.json"),
            vec!["asupersync lab replay --seed 42".to_string()],
            None,
        );
        assert_eq!(report.trace_id, "trace-browser-ok");
        assert_eq!(report.event_count, 2);
        assert_eq!(report.replayed_events, 2);
        assert!(report.completed);
        assert!(report.divergence_index.is_none());
        assert!(report.minimization_prefix_len.is_none());
        assert_eq!(
            report.artifact_pointer,
            Some("artifacts/replay/browser-ok.json".to_string())
        );

        let json = report.to_json_pretty().expect("serialize report");
        assert!(json.contains("trace-browser-ok"));
        assert!(json.contains("rerun_commands"));
    }

    #[test]
    fn browser_replay_report_with_divergence_includes_minimization_hint() {
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ];
        let replayer = TraceReplayer::new(make_trace(events));
        let bad = ReplayEvent::RngSeed { seed: 999 };
        let divergence = replayer.verify(&bad).expect_err("expected divergence");
        let report = replayer.browser_replay_report(
            "trace-browser-div",
            None::<&str>,
            vec!["asupersync lab replay --seed 42 --window-start 0 --window-events 1".to_string()],
            Some(&divergence),
        );
        assert_eq!(report.divergence_index, Some(0));
        assert!(report.divergence_context.is_some());
        assert_eq!(report.minimization_prefix_len, Some(1));
        assert_eq!(report.minimization_reduction_pct, Some(66));
        assert!(!report.rerun_commands.is_empty());
    }
