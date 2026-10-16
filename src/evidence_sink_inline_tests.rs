    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use franken_evidence::EvidenceLedgerBuilder;
    use std::sync::Arc;

    fn test_entry(component: &str) -> EvidenceLedger {
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_000_000)
            .component(component)
            .action("test_action")
            .posterior(vec![0.6, 0.4])
            .chosen_expected_loss(0.1)
            .calibration_score(0.85)
            .build()
            .unwrap()
    }

    #[test]
    fn null_sink_accepts_entries() {
        let sink = NullSink;
        sink.emit(&test_entry("scheduler"));
    }

    #[test]
    fn collector_sink_captures_entries() {
        let sink = CollectorSink::new();
        assert!(sink.is_empty());

        sink.emit(&test_entry("scheduler"));
        sink.emit(&test_entry("cancel"));

        assert_eq!(sink.len(), 2);
        let entries = sink.entries();
        assert_eq!(entries[0].component, "scheduler");
        assert_eq!(entries[1].component, "cancel");
    }

    #[test]
    fn collector_sink_as_trait_object() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        sink.emit(&test_entry("budget"));
    }

    #[test]
    fn jsonl_sink_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");

        let sink = JsonlSink::open(path.clone()).unwrap();
        sink.emit(&test_entry("scheduler"));
        sink.emit(&test_entry("cancel"));

        let entries = franken_evidence::export::read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component, "scheduler");
        assert_eq!(entries[1].component, "cancel");
    }

    // ---- emit helpers ----

    #[test]
    fn emit_scheduler_evidence_populates_fields() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "cancel_lane", 10, 5, 3, false);

        assert_eq!(sink.len(), 1);
        let entry = &sink.entries()[0];
        assert_eq!(entry.component, "scheduler");
        assert_eq!(entry.action, "cancel_lane");
        assert!(!entry.fallback_active);
        assert!(
            (entry.calibration_score - 1.0).abs() < f64::EPSILON,
            "expected 1.0, got {}",
            entry.calibration_score
        );
        // posterior should sum to ~1.0
        let sum: f64 = entry.posterior.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "posterior sum={sum}");
        assert_eq!(
            entry.expected_loss_by_action.get("cancel_lane"),
            Some(&10.0)
        );
        assert!((entry.chosen_expected_loss - 10.0).abs() < f64::EPSILON);
        // top_features should include depth values
        assert_eq!(entry.top_features.len(), 3);
    }

    #[test]
    fn emit_scheduler_evidence_fallback_sets_calibration_zero() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "ready_lane", 0, 0, 1, true);

        let entry = &sink.entries()[0];
        assert!(entry.fallback_active);
        assert!(
            (entry.calibration_score).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            entry.calibration_score
        );
    }

    #[test]
    fn emit_scheduler_evidence_all_zero_depths() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "idle", 0, 0, 0, false);

        let entry = &sink.entries()[0];
        // All-zero depths: posterior should be [0, 0, 0] (0/max(1,0))
        assert_eq!(entry.posterior.len(), 3);
        // denominator is max(1, 0+0+0) = 1, so all zeros
        for &p in &entry.posterior {
            assert!((p).abs() < f64::EPSILON, "expected 0.0, got {p}");
        }
        assert_eq!(entry.expected_loss_by_action.get("idle"), Some(&0.0));
        assert!((entry.chosen_expected_loss).abs() < f64::EPSILON);
    }

    #[test]
    fn emit_cancel_evidence_populates_fields() {
        let sink = CollectorSink::new();
        emit_cancel_evidence(&sink, "user", 5, 2);

        assert_eq!(sink.len(), 1);
        let entry = &sink.entries()[0];
        assert_eq!(entry.component, "cancellation");
        assert_eq!(entry.action, "cancel_user");
        assert_eq!(entry.posterior, vec![1.0]);
        assert!(!entry.fallback_active);
        assert_eq!(entry.top_features.len(), 2);
        assert_eq!(entry.top_features[0].0, "cleanup_poll_quota");
        assert!(
            (entry.top_features[0].1 - 5.0).abs() < f64::EPSILON,
            "expected 5.0, got {}",
            entry.top_features[0].1
        );
        assert_eq!(entry.top_features[1].0, "cleanup_priority");
        assert!(
            (entry.top_features[1].1 - 2.0).abs() < f64::EPSILON,
            "expected 2.0, got {}",
            entry.top_features[1].1
        );
    }

    #[test]
    fn emit_budget_evidence_with_deadline() {
        let sink = CollectorSink::new();
        emit_budget_evidence(&sink, "poll", 0, Some(500));

        assert_eq!(sink.len(), 1);
        let entry = &sink.entries()[0];
        assert_eq!(entry.component, "budget");
        assert_eq!(entry.action, "exhausted_poll");
        assert!(
            (entry.top_features[0].1).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            entry.top_features[0].1
        ); // polls_remaining
        assert!(
            (entry.top_features[1].1 - 500.0).abs() < f64::EPSILON,
            "expected 500.0, got {}",
            entry.top_features[1].1
        ); // deadline_remaining_ms
    }

    #[test]
    fn emit_budget_evidence_without_deadline() {
        let sink = CollectorSink::new();
        emit_budget_evidence(&sink, "time", 10, None);

        let entry = &sink.entries()[0];
        assert_eq!(entry.action, "exhausted_time");
        // None deadline -> u64::MAX as f64
        #[allow(clippy::cast_precision_loss, clippy::float_cmp)]
        {
            assert_eq!(entry.top_features[1].1, u64::MAX as f64);
        }
    }

    #[test]
    fn emit_helpers_use_deterministic_timestamp_sequence() {
        let sink = CollectorSink::new();

        emit_scheduler_evidence(&sink, "ready_lane", 1, 2, 3, false);
        emit_cancel_evidence(&sink, "user", 5, 2);
        emit_budget_evidence(&sink, "time", 10, Some(50));

        let timestamps: Vec<u64> = sink
            .entries()
            .iter()
            .map(|entry| entry.ts_unix_ms)
            .collect();
        assert_eq!(timestamps, vec![1, 2, 3]);
    }

    // ---- CollectorSink ----

    #[test]
    fn collector_sink_default_is_empty() {
        let sink = CollectorSink::default();
        assert!(sink.is_empty());
        assert_eq!(sink.len(), 0);
        assert!(sink.entries().is_empty());
    }

    #[test]
    fn collector_sink_debug_impl() {
        let sink = CollectorSink::new();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("CollectorSink"), "{dbg}");
    }

    // ---- NullSink ----

    #[test]
    fn null_sink_is_clone_and_copy() {
        let a = NullSink;
        let b = a;
        let c = a;
        // All are usable (Copy + Clone)
        b.emit(&test_entry("x"));
        c.emit(&test_entry("y"));
    }

    #[test]
    fn null_sink_debug_impl() {
        let dbg = format!("{NullSink:?}");
        assert_eq!(dbg, "NullSink");
    }

    // ---- JsonlSink ----

    #[test]
    fn jsonl_sink_path_returns_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");
        let sink = JsonlSink::open(path.clone()).unwrap();
        assert_eq!(sink.path(), path);
    }

    #[test]
    fn jsonl_sink_debug_contains_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("debug_test.jsonl");
        let sink = JsonlSink::open(path).unwrap();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("JsonlSink"), "{dbg}");
        assert!(dbg.contains("debug_test.jsonl"), "{dbg}");
    }

    #[test]
    fn jsonl_sink_appends_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.jsonl");

        let sink = JsonlSink::open(path.clone()).unwrap();
        for i in 0..5 {
            sink.emit(&test_entry(&format!("comp_{i}")));
        }

        let entries = franken_evidence::export::read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 5);
        for (i, entry) in entries.iter().enumerate().take(5) {
            assert_eq!(entry.component, format!("comp_{i}"));
        }
    }

    // ---- Gap tests ----

    #[test]
    fn collector_sink_entries_fifo_order() {
        let sink = CollectorSink::new();
        for name in &["a", "b", "c", "d", "e"] {
            sink.emit(&test_entry(name));
        }
        let entries = sink.entries();
        let names: Vec<&str> = entries.iter().map(|e| e.component.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn emit_scheduler_evidence_expected_loss_tracks_chosen_action() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "drain_obligations", 10, 5, 3, false);

        let entry = &sink.entries()[0];
        let map = &entry.expected_loss_by_action;

        assert_eq!(map.len(), 1);
        assert_eq!(map.get("drain_obligations"), Some(&10.0));
        assert!((entry.chosen_expected_loss - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn collector_sink_concurrent_access() {
        let sink = Arc::new(CollectorSink::new());
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let sink = Arc::clone(&sink);
            handles.push(std::thread::spawn(move || {
                for i in 0..25u32 {
                    let component = format!("t{t}_i{i}");
                    sink.emit(&{
                        EvidenceLedgerBuilder::new()
                            .ts_unix_ms(1_700_000_000_000 + u64::from(t * 100 + i))
                            .component(&component)
                            .action("concurrent_test")
                            .posterior(vec![1.0])
                            .chosen_expected_loss(0.0)
                            .calibration_score(1.0)
                            .build()
                            .unwrap()
                    });
                }
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(sink.len(), 100, "expected 100 entries, got {}", sink.len());
    }

    /// br-asupersync-n1g6sm — `next_evidence_ts` must produce strictly
    /// distinct values across the wrap boundary. The previous shape
    /// (`saturating_add(1)`) collided at u64::MAX (two consecutive
    /// calls returned the same value). We test only the small-counter
    /// regime here — the wrap-collision argument is structural in the
    /// switch from saturating_add to wrapping_add.
    #[test]
    fn next_evidence_ts_is_distinct_for_consecutive_calls() {
        let sink = CollectorSink::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1024 {
            let ts = sink.next_evidence_ts();
            assert!(seen.insert(ts), "ts {ts} collided with prior call");
        }
    }
