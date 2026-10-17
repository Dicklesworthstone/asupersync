    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{Budget, ObligationId, RegionId, TaskId, Time};
    use crate::util::ArenaIndex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn obligation(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn empty_runtime_is_deterministic() {
        init_test("empty_runtime_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |_runtime| {
            // Do nothing
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("empty_runtime_is_deterministic");
    }

    #[test]
    fn time_advance_is_deterministic() {
        init_test("time_advance_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |runtime| {
            runtime.advance_time(1_000_000);
            runtime.advance_time(2_000_000);
            runtime.advance_time(3_000_000);
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("time_advance_is_deterministic");
    }

    #[test]
    fn region_creation_is_deterministic() {
        init_test("region_creation_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |runtime| {
            let _root = runtime.state.create_root_region(Budget::INFINITE);
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("region_creation_is_deterministic");
    }

    #[test]
    fn run_until_quiescent_is_deterministic() {
        init_test("run_until_quiescent_is_deterministic");
        let config = LabConfig::new(42);
        let oracle = DeterminismOracle::new();

        let result = oracle.verify(config, |runtime| {
            runtime.run_until_quiescent();
        });

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("run_until_quiescent_is_deterministic");
    }

    #[test]
    fn rng_seeded_deterministically() {
        init_test("rng_seeded_deterministically");
        // Verify that the RNG produces identical sequences
        let config = LabConfig::new(12345);

        let mut r1 = LabRuntime::new(config.clone());
        let mut r2 = LabRuntime::new(config);

        // Run some steps which consume RNG state
        for _ in 0..100 {
            r1.step_for_test();
        }
        for _ in 0..100 {
            r2.step_for_test();
        }

        // Traces should be identical
        let trace1: Vec<_> = r1
            .trace()
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
            .collect();
        let trace2: Vec<_> = r2
            .trace()
            .snapshot()
            .into_iter()
            .map(|e| TraceEventSummary::from_event(&e))
            .collect();

        let oracle = DeterminismOracle::new();
        let ok = oracle.compare_traces(&trace1, &trace2).is_ok();
        crate::assert_with_log!(ok, "traces ok", true, ok);
        crate::test_complete!("rng_seeded_deterministically");
    }

    #[test]
    fn multi_run_determinism() {
        init_test("multi_run_determinism");
        let config = LabConfig::new(999);
        assert_deterministic_multi(&config, 5, |runtime| {
            runtime.advance_time(1_000);
            runtime.run_until_quiescent();
        });
        crate::test_complete!("multi_run_determinism");
    }

    #[test]
    fn violation_reports_divergence_correctly() {
        init_test("violation_reports_divergence_correctly");
        let oracle = DeterminismOracle::new().context_window(3);

        // Create two traces that diverge
        let trace1 = vec![
            TraceEventSummary {
                seq: 0,
                time_nanos: 0,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=hello".to_string(),
            },
            TraceEventSummary {
                seq: 1,
                time_nanos: 100,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=world".to_string(),
            },
            TraceEventSummary {
                seq: 2,
                time_nanos: 200,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=foo".to_string(),
            },
        ];

        let trace2 = vec![
            TraceEventSummary {
                seq: 0,
                time_nanos: 0,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=hello".to_string(),
            },
            TraceEventSummary {
                seq: 1,
                time_nanos: 100,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=world".to_string(),
            },
            TraceEventSummary {
                seq: 2,
                time_nanos: 200,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=bar".to_string(), // Different!
            },
        ];

        let result = oracle.compare_traces(&trace1, &trace2);
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.divergence_index == 2,
            "divergence_index",
            2,
            violation.divergence_index
        );
        let expected = violation.expected.unwrap().data_summary;
        crate::assert_with_log!(expected == "msg=foo", "expected", "msg=foo", expected);
        let actual = violation.actual.unwrap().data_summary;
        crate::assert_with_log!(actual == "msg=bar", "actual", "msg=bar", actual);
        let ctx_len = violation.context_before.len();
        crate::assert_with_log!(ctx_len == 2, "context len", 2, ctx_len); // Events 0 and 1
        crate::test_complete!("violation_reports_divergence_correctly");
    }

    #[test]
    fn violation_handles_different_lengths() {
        init_test("violation_handles_different_lengths");
        let oracle = DeterminismOracle::new();

        let trace1 = vec![
            TraceEventSummary {
                seq: 0,
                time_nanos: 0,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=a".to_string(),
            },
            TraceEventSummary {
                seq: 1,
                time_nanos: 100,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=b".to_string(),
            },
        ];

        let trace2 = vec![TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=a".to_string(),
        }];

        let result = oracle.compare_traces(&trace1, &trace2);
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.divergence_index == 1,
            "divergence_index",
            1,
            violation.divergence_index
        );
        let expected_some = violation.expected.is_some();
        crate::assert_with_log!(expected_some, "expected some", true, expected_some);
        let actual_none = violation.actual.is_none();
        crate::assert_with_log!(actual_none, "actual none", true, actual_none);
        crate::test_complete!("violation_handles_different_lengths");
    }

    #[test]
    fn trace_event_summary_equality() {
        init_test("trace_event_summary_equality");
        let s1 = TraceEventSummary {
            seq: 0,
            time_nanos: 100,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0) region=Region(0)".to_string(),
        };

        let s2 = TraceEventSummary {
            seq: 0,
            time_nanos: 100,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0) region=Region(0)".to_string(),
        };

        crate::assert_with_log!(s1 == s2, "equal", s2, s1);

        let s3 = TraceEventSummary {
            seq: 1, // Different seq
            time_nanos: 100,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0) region=Region(0)".to_string(),
        };

        let neq = s1 != s3;
        crate::assert_with_log!(neq, "not equal", true, neq);
        crate::test_complete!("trace_event_summary_equality");
    }

    #[test]
    fn determinism_violation_debug_clone() {
        init_test("determinism_violation_debug_clone");
        let v = DeterminismViolation {
            divergence_index: 5,
            expected: None,
            actual: None,
            context_before: vec![],
            context_after_expected: vec![],
            context_after_actual: vec![],
            source_hint: DeterminismSourceHint::TraceLength,
            trace1_len: 10,
            trace2_len: 8,
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("DeterminismViolation"));
        let v2 = v;
        assert_eq!(v2.divergence_index, 5);
        assert_eq!(v2.trace1_len, 10);
        assert_eq!(v2.trace2_len, 8);
        crate::test_complete!("determinism_violation_debug_clone");
    }

    #[test]
    fn determinism_violation_display_both_none() {
        init_test("determinism_violation_display_both_none");
        let v = DeterminismViolation {
            divergence_index: 0,
            expected: None,
            actual: None,
            context_before: vec![],
            context_after_expected: vec![],
            context_after_actual: vec![],
            source_hint: DeterminismSourceHint::TraceLength,
            trace1_len: 0,
            trace2_len: 0,
        };
        let display = format!("{v}");
        assert!(display.contains("[ASUP-E403] Determinism violation at index 0"));
        assert!(display.contains("determinism.checklist.trace-length"));
        assert!(display.contains("<end of trace>"));
        crate::test_complete!("determinism_violation_display_both_none");
    }

    #[test]
    fn determinism_violation_display_with_events() {
        init_test("determinism_violation_display_with_events");
        let v = DeterminismViolation {
            divergence_index: 3,
            expected: Some(TraceEventSummary {
                seq: 3,
                time_nanos: 300,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=expected".into(),
            }),
            actual: Some(TraceEventSummary {
                seq: 3,
                time_nanos: 300,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=actual".into(),
            }),
            context_before: vec![TraceEventSummary {
                seq: 2,
                time_nanos: 200,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=context".into(),
            }],
            context_after_expected: vec![TraceEventSummary {
                seq: 4,
                time_nanos: 400,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=expected-next".into(),
            }],
            context_after_actual: vec![TraceEventSummary {
                seq: 4,
                time_nanos: 400,
                kind: TraceEventKind::UserTrace,
                data_summary: "msg=actual-next".into(),
            }],
            source_hint: DeterminismSourceHint::UserTrace,
            trace1_len: 5,
            trace2_len: 5,
        };
        let display = format!("{v}");
        assert!(display.contains("index 3"));
        assert!(display.contains("Expected:"));
        assert!(display.contains("Actual:"));
        assert!(display.contains("Context"));
        assert!(display.contains("Expected context after divergence"));
        assert!(display.contains("Actual context after divergence"));
        assert!(display.contains("determinism.checklist.user-trace"));
        crate::test_complete!("determinism_violation_display_with_events");
    }

    #[test]
    fn determinism_violation_is_error() {
        init_test("determinism_violation_is_error");
        let v = DeterminismViolation {
            divergence_index: 0,
            expected: None,
            actual: None,
            context_before: vec![],
            context_after_expected: vec![],
            context_after_actual: vec![],
            source_hint: DeterminismSourceHint::Unknown,
            trace1_len: 0,
            trace2_len: 0,
        };
        // Verify it implements std::error::Error
        let err: &dyn std::error::Error = &v;
        let display = format!("{err}");
        assert!(display.contains("Determinism violation"));
        crate::test_complete!("determinism_violation_is_error");
    }

    #[test]
    fn trace_event_summary_debug_clone() {
        init_test("trace_event_summary_debug_clone");
        let s = TraceEventSummary {
            seq: 42,
            time_nanos: 1000,
            kind: TraceEventKind::Spawn,
            data_summary: "task=Task(0)".into(),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TraceEventSummary"));
        let s2 = s;
        assert_eq!(s2.seq, 42);
        assert_eq!(s2.time_nanos, 1000);
        assert_eq!(s2.data_summary, "task=Task(0)");
        crate::test_complete!("trace_event_summary_debug_clone");
    }

    #[test]
    fn trace_event_summary_display() {
        init_test("trace_event_summary_display");
        let s = TraceEventSummary {
            seq: 0,
            time_nanos: 100,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=hello".into(),
        };
        let display = format!("{s}");
        assert!(display.contains("seq=0"));
        assert!(display.contains("time=100"));
        assert!(display.contains("msg=hello"));
        crate::test_complete!("trace_event_summary_display");
    }

    #[test]
    fn trace_event_summary_display_empty_data() {
        init_test("trace_event_summary_display_empty_data");
        let s = TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: String::new(),
        };
        let display = format!("{s}");
        assert!(display.contains("seq=0"));
        // Empty data should not add extra content
        assert!(!display.contains("  "));
        crate::test_complete!("trace_event_summary_display_empty_data");
    }

    #[test]
    fn worker_summary_distinguishes_decision_and_replay_identity() {
        init_test("worker_summary_distinguishes_decision_and_replay_identity");

        let event_a = TraceEvent::new(
            7,
            Time::from_nanos(123),
            TraceEventKind::WorkerDrainCompleted,
            TraceData::Worker {
                worker_id: "worker-a".to_string(),
                job_id: 11,
                decision_seq: 17,
                replay_hash: 23,
                task: task(1),
                region: region(2),
                obligation: obligation(3),
            },
        );
        let event_b = TraceEvent::new(
            7,
            Time::from_nanos(123),
            TraceEventKind::WorkerDrainCompleted,
            TraceData::Worker {
                worker_id: "worker-a".to_string(),
                job_id: 11,
                decision_seq: 99,
                replay_hash: 1001,
                task: task(1),
                region: region(2),
                obligation: obligation(3),
            },
        );

        let summary_a = TraceEventSummary::from_event(&event_a);
        let summary_b = TraceEventSummary::from_event(&event_b);

        assert_ne!(summary_a.data_summary, summary_b.data_summary);
        assert_ne!(summary_a, summary_b);
        assert!(summary_a.data_summary.contains("decision_seq=17"));
        assert!(summary_a.data_summary.contains("replay_hash=23"));
        assert!(summary_b.data_summary.contains("decision_seq=99"));
        assert!(summary_b.data_summary.contains("replay_hash=1001"));
        crate::test_complete!("worker_summary_distinguishes_decision_and_replay_identity");
    }

    #[test]
    fn determinism_oracle_debug_default() {
        init_test("determinism_oracle_debug_default");
        let oracle = DeterminismOracle::default();
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("DeterminismOracle"));
        crate::test_complete!("determinism_oracle_debug_default");
    }

    #[test]
    fn determinism_oracle_context_window_builder() {
        init_test("determinism_oracle_context_window_builder");
        let oracle = DeterminismOracle::new().context_window(10);
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("10"));
        crate::test_complete!("determinism_oracle_context_window_builder");
    }

    #[test]
    fn determinism_oracle_identical_traces_ok() {
        init_test("determinism_oracle_identical_traces_ok");
        let oracle = DeterminismOracle::new();
        let trace = vec![TraceEventSummary {
            seq: 0,
            time_nanos: 0,
            kind: TraceEventKind::UserTrace,
            data_summary: "msg=test".into(),
        }];
        let result = oracle.compare_traces(&trace, &trace);
        assert!(result.is_ok());
        crate::test_complete!("determinism_oracle_identical_traces_ok");
    }

    #[test]
    fn determinism_oracle_empty_traces_ok() {
        init_test("determinism_oracle_empty_traces_ok");
        let oracle = DeterminismOracle::new();
        let result = oracle.compare_traces(&[], &[]);
        assert!(result.is_ok());
        crate::test_complete!("determinism_oracle_empty_traces_ok");
    }

    fn record_message(runtime: &LabRuntime, message: String) {
        runtime.trace().record_event(|seq| {
            TraceEvent::new(
                seq,
                Time::ZERO,
                TraceEventKind::UserTrace,
                TraceData::Message(message),
            )
        });
    }

    /// A message summary keeps the whole message. Cut at byte 100, it
    /// panicked inside a multi-byte character (br-asupersync-vcu2oz M5).
    #[test]
    fn a_message_is_summarized_whole_across_a_multibyte_character() {
        init_test("a_message_is_summarized_whole_across_a_multibyte_character");
        // 'é' takes bytes 99 and 100, so a cut at byte 100 splits it.
        let message = format!("{}é tail", "x".repeat(99));
        let summary = TraceEventSummary::from_event(&TraceEvent::new(
            0,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message(message.clone()),
        ));
        assert_eq!(summary.data_summary, format!("msg={message}"));
        crate::test_complete!("a_message_is_summarized_whole_across_a_multibyte_character");
    }

    /// Runs whose messages differ after byte 100 diverge. The 100-byte prefix
    /// compared them as equal (br-asupersync-vcu2oz M5).
    #[test]
    fn messages_that_differ_after_byte_100_diverge() {
        init_test("messages_that_differ_after_byte_100_diverge");
        let runs = AtomicUsize::new(0);
        let result = DeterminismOracle::new().verify(LabConfig::new(42), |runtime| {
            let run = runs.fetch_add(1, Ordering::SeqCst);
            record_message(runtime, format!("{}{run}", "x".repeat(120)));
        });
        assert!(result.is_err(), "the messages differ at byte 120");
        crate::test_complete!("messages_that_differ_after_byte_100_diverge");
    }

    /// Traces that overflow the buffer are compared whole: a divergence among
    /// the events the buffer evicted is reported, and identical runs still
    /// pass. Only the newest `trace_capacity` events were compared, so these
    /// runs passed (br-asupersync-vcu2oz M5).
    #[test]
    fn a_divergence_the_trace_buffer_evicted_is_detected() {
        init_test("a_divergence_the_trace_buffer_evicted_is_detected");
        let config = LabConfig::new(42).trace_capacity(8);
        let runs = AtomicUsize::new(0);
        let result = DeterminismOracle::new().verify(config.clone(), |runtime| {
            let run = runs.fetch_add(1, Ordering::SeqCst);
            record_message(runtime, format!("early {run}"));
            for i in 0..32 {
                record_message(runtime, format!("late {i}"));
            }
        });
        let violation = result.expect_err("the first message differs in every run");
        assert!(
            violation
                .expected
                .as_ref()
                .is_some_and(|event| event.data_summary.starts_with("msg=early")),
            "the divergence is the evicted first message: {violation}"
        );

        let identical = DeterminismOracle::new().verify(config, |runtime| {
            for i in 0..40 {
                record_message(runtime, format!("same {i}"));
            }
        });
        assert!(identical.is_ok(), "identical overflowing runs pass");
        crate::test_complete!("a_divergence_the_trace_buffer_evicted_is_detected");
    }

    #[test]
    #[should_panic(expected = "Determinism check failed on run 2 of 3")]
    fn assert_deterministic_multi_compares_the_evicted_events() {
        let runs = AtomicUsize::new(0);
        assert_deterministic_multi(&LabConfig::new(42).trace_capacity(8), 3, |runtime| {
            let run = runs.fetch_add(1, Ordering::SeqCst);
            record_message(runtime, format!("early {run}"));
            for i in 0..32 {
                record_message(runtime, format!("late {i}"));
            }
        });
    }
