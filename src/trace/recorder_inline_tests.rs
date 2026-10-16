    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_task_id(index: u32, generation: u32) -> TaskId {
        TaskId::new_for_test(index, generation)
    }

    fn make_region_id(index: u32, generation: u32) -> RegionId {
        RegionId::new_for_test(index, generation)
    }

    fn scrub_replay_trace_for_snapshot_test(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut scrubbed = serde_json::Map::with_capacity(map.len());
                for (key, value) in map {
                    let replacement = match key.as_str() {
                        "recorded_at" => Value::String("[TIMESTAMP]".to_string()),
                        "task" | "region" | "parent" => match value {
                            Value::Null => Value::Null,
                            _ => Value::String("[ID]".to_string()),
                        },
                        _ => scrub_replay_trace_for_snapshot_test(value),
                    };
                    scrubbed.insert(key, replacement);
                }
                Value::Object(scrubbed)
            }
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(scrub_replay_trace_for_snapshot_test)
                    .collect(),
            ),
            other => other,
        }
    }

    #[test]
    fn disabled_recorder_is_noop() {
        let mut recorder = TraceRecorder::disabled();
        assert!(!recorder.is_enabled());
        assert_eq!(recorder.event_count(), 0);

        // These should all be no-ops
        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        recorder.record_rng_seed(42);
        recorder.record_rng_value(123);

        assert_eq!(recorder.event_count(), 0);
        assert!(recorder.finish().is_none());
    }

    #[test]
    fn enabled_recorder_captures_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        assert!(recorder.is_enabled());

        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        recorder.record_task_completed(make_task_id(1, 0), Severity::Ok);

        assert_eq!(recorder.event_count(), 4);

        let trace = recorder.finish().expect("should have trace");
        assert_eq!(trace.events.len(), 4);
        assert_eq!(trace.metadata.seed, 42);
    }

    #[test]
    fn rng_recording_can_be_disabled() {
        let config = RecorderConfig::enabled().with_rng(false);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        // Seed is always recorded
        recorder.record_rng_seed(42);
        // But values are not
        recorder.record_rng_value(123);
        recorder.record_rng_value(456);

        assert_eq!(recorder.event_count(), 1); // Only the seed
    }

    #[test]
    fn waker_recording_can_be_disabled() {
        let config = RecorderConfig::enabled().with_wakers(false);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_waker_wake(make_task_id(1, 0));
        recorder.record_waker_batch_wake(5);

        assert_eq!(recorder.event_count(), 0);
    }

    #[test]
    fn time_advancement_deduplication() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        // Same time should not be recorded
        recorder.record_time_advanced(Time::ZERO, Time::ZERO);
        assert_eq!(recorder.event_count(), 0);

        // Different time should be recorded
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        assert_eq!(recorder.event_count(), 1);
    }

    #[test]
    fn seed_only_recorded_once() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_rng_seed(42);
        recorder.record_rng_seed(42); // Duplicate should be ignored
        recorder.record_rng_seed(99); // Different value also ignored

        assert_eq!(recorder.event_count(), 1);
    }

    #[test]
    fn take_resets_recorder() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        assert_eq!(recorder.event_count(), 2);

        let trace1 = recorder.take().expect("should have trace");
        assert_eq!(trace1.events.len(), 2);

        // Recorder should be reset but still enabled
        assert!(recorder.is_enabled());
        assert_eq!(recorder.event_count(), 0);

        // Can record new events
        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        assert_eq!(recorder.event_count(), 2);
    }

    #[test]
    fn take_rotates_recorded_at_deterministically() {
        let mut metadata = TraceMetadata::new(42)
            .with_config_hash(7)
            .with_description("deterministic take");
        metadata.recorded_at = 123;
        let mut recorder = TraceRecorder::new(metadata);

        recorder.record_rng_seed(42);
        let trace1 = recorder.take().expect("should have first trace");
        assert_eq!(trace1.metadata.recorded_at, 123);
        assert_eq!(trace1.metadata.config_hash, 7);
        assert_eq!(
            trace1.metadata.description.as_deref(),
            Some("deterministic take")
        );

        recorder.record_rng_seed(42);
        let trace2 = recorder.take().expect("should have second trace");
        assert_eq!(trace2.metadata.recorded_at, 124);
        assert_eq!(trace2.metadata.config_hash, 7);
        assert_eq!(
            trace2.metadata.description.as_deref(),
            Some("deterministic take")
        );

        recorder.record_rng_seed(42);
        let trace3 = recorder.finish().expect("should have third trace");
        assert_eq!(trace3.metadata.recorded_at, 125);
        assert_eq!(trace3.metadata.config_hash, 7);
        assert_eq!(
            trace3.metadata.description.as_deref(),
            Some("deterministic take")
        );
    }

    #[test]
    fn chaos_injections() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        let task = make_task_id(1, 0);
        recorder.record_cancel_injection(task);
        recorder.record_delay_injection(Some(task), 1_000_000);
        recorder.record_wakeup_storm_injection(task, 10);
        recorder.record_budget_exhaust_injection(task);

        assert_eq!(recorder.event_count(), 4);

        let trace = recorder.finish().expect("trace");

        // Verify the chaos events
        match &trace.events[0] {
            ReplayEvent::ChaosInjection { kind, .. } => {
                assert_eq!(*kind, chaos_kind::CANCEL);
            }
            _ => panic!("expected ChaosInjection"),
        }
    }

    #[test]
    fn io_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_io_ready(1, true, false, false, false);
        recorder.record_io_result(1, 100);
        recorder.record_io_error(2, io::ErrorKind::ConnectionRefused);

        assert_eq!(recorder.event_count(), 3);

        let trace = recorder.finish().expect("trace");

        match &trace.events[0] {
            ReplayEvent::IoReady { token, readiness } => {
                assert_eq!(*token, 1);
                assert_eq!(*readiness & 1, 1); // readable
            }
            _ => panic!("expected IoReady"),
        }

        match &trace.events[1] {
            ReplayEvent::IoResult { token, bytes } => {
                assert_eq!(*token, 1);
                assert_eq!(*bytes, 100);
            }
            _ => panic!("expected IoResult"),
        }
    }

    #[test]
    fn task_lifecycle() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        let task = make_task_id(1, 0);
        let region = make_region_id(0, 0);

        recorder.record_task_spawned(task, region, 0);
        recorder.record_task_scheduled(task, 0);
        recorder.record_task_yielded(task);
        recorder.record_task_scheduled(task, 1);
        recorder.record_task_completed(task, Severity::Ok);

        assert_eq!(recorder.event_count(), 5);

        let trace = recorder.finish().expect("trace");

        // Verify sequence
        assert!(matches!(trace.events[0], ReplayEvent::TaskSpawned { .. }));
        assert!(matches!(trace.events[1], ReplayEvent::TaskScheduled { .. }));
        assert!(matches!(trace.events[2], ReplayEvent::TaskYielded { .. }));
        assert!(matches!(trace.events[3], ReplayEvent::TaskScheduled { .. }));
        assert!(matches!(trace.events[4], ReplayEvent::TaskCompleted { .. }));
    }

    #[test]
    fn timer_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        recorder.record_timer_created(1, Time::from_millis(100));
        recorder.record_timer_fired(1);
        recorder.record_timer_created(2, Time::from_millis(200));
        recorder.record_timer_cancelled(2);

        assert_eq!(recorder.event_count(), 4);

        let trace = recorder.finish().expect("trace");

        assert!(matches!(
            trace.events[0],
            ReplayEvent::TimerCreated { timer_id: 1, .. }
        ));
        assert!(matches!(
            trace.events[1],
            ReplayEvent::TimerFired { timer_id: 1 }
        ));
        assert!(matches!(
            trace.events[2],
            ReplayEvent::TimerCreated { timer_id: 2, .. }
        ));
        assert!(matches!(
            trace.events[3],
            ReplayEvent::TimerCancelled { timer_id: 2 }
        ));
    }

    #[test]
    fn estimated_size() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));

        // Empty trace has some overhead
        let base_size = recorder.estimated_size();
        assert!(base_size > 0);

        // Add events and size should grow
        for i in 0..100 {
            recorder.record_task_scheduled(make_task_id(i, 0), u64::from(i));
        }

        let with_events = recorder.estimated_size();
        assert!(with_events > base_size);
        assert!(with_events < 5000); // Should be compact
    }

    #[test]
    fn max_events_stop_recording() {
        let config = RecorderConfig::enabled()
            .with_max_events(Some(2))
            .on_limit(LimitAction::StopRecording);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        assert_eq!(recorder.event_count(), 2);
        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 2);
    }

    #[test]
    fn max_events_drop_oldest() {
        let config = RecorderConfig::enabled()
            .with_max_events(Some(2))
            .on_limit(LimitAction::DropOldest);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 2);
        match (&trace.events[0], &trace.events[1]) {
            (
                ReplayEvent::TaskScheduled { at_tick: first, .. },
                ReplayEvent::TaskScheduled {
                    at_tick: second, ..
                },
            ) => {
                assert_eq!(*first, 1);
                assert_eq!(*second, 2);
            }
            _ => panic!("unexpected events for drop-oldest"),
        }
    }

    #[test]
    fn max_memory_stop_recording() {
        let config = RecorderConfig::enabled()
            .with_max_memory(20)
            .on_limit(LimitAction::StopRecording);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);

        assert_eq!(recorder.event_count(), 1);
        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 1);
    }

    #[test]
    fn limit_callback_invoked() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hit_ref = Arc::clone(&hits);
        let action = LimitAction::Callback(Arc::new(move |_info| {
            hit_ref.fetch_add(1, Ordering::SeqCst);
            LimitAction::StopRecording
        }));

        let config = RecorderConfig::enabled()
            .with_max_events(Some(1))
            .on_limit(action);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(recorder.event_count(), 1);
    }

    // ── snapshot ───────────────────────────────────────────────────

    #[test]
    fn snapshot_returns_clone_of_events() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_rng_seed(42);
        recorder.record_task_scheduled(make_task_id(1, 0), 0);

        let snap = recorder.snapshot().expect("should have snapshot");
        assert_eq!(snap.events.len(), 2);

        // Recording more events doesn't affect snapshot
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(recorder.event_count(), 3);
    }

    #[test]
    fn snapshot_on_disabled_returns_none() {
        let recorder = TraceRecorder::disabled();
        assert!(recorder.snapshot().is_none());
    }

    #[test]
    fn snapshot_scrubs_ids_and_recorded_at() {
        let mut metadata = TraceMetadata::new(42)
            .with_config_hash(0xfeed_beef)
            .with_description("trace recorder snapshot");
        metadata.recorded_at = 1_726_133_456_789_000_000;
        let mut recorder = TraceRecorder::new(metadata);

        let task = make_task_id(7, 3);
        let region = make_region_id(4, 1);

        recorder.record_rng_seed(42);
        recorder.record_task_spawned(task, region, 0);
        recorder.record_task_scheduled(task, 1);
        recorder.record_time_advanced(Time::from_nanos(10), Time::from_nanos(75));
        recorder.record_io_ready(17, true, true, false, false);
        recorder.record_delay_injection(Some(task), 50_000);
        recorder.record_waker_batch_wake(3);

        let snapshot = recorder.snapshot().expect("should have snapshot");

        insta::assert_json_snapshot!(
            "trace_recorder_snapshot_scrubbed",
            scrub_replay_trace_for_snapshot_test(serde_json::to_value(&snapshot).unwrap())
        );
    }

    // ── take on disabled ───────────────────────────────────────────

    #[test]
    fn take_on_disabled_returns_none() {
        let mut recorder = TraceRecorder::disabled();
        assert!(recorder.take().is_none());
    }

    // ── io_ready bitflags ──────────────────────────────────────────

    #[test]
    fn io_ready_writable_flag() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, true, false, false);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { token, readiness } => {
                assert_eq!(*token, 10);
                assert_eq!(*readiness, 2); // writable = bit 1
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_error_flag() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, false, true, false);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 4); // error = bit 2
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_hangup_flag() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, false, false, true);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 8); // hangup = bit 3
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_all_flags() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, true, true, true, true);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 0x0F); // all bits set
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    #[test]
    fn io_ready_no_flags() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_ready(10, false, false, false, false);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::IoReady { readiness, .. } => {
                assert_eq!(*readiness, 0);
            }
            other => panic!("expected IoReady, got {other:?}"),
        }
    }

    // ── chaos injection variants ───────────────────────────────────

    #[test]
    fn delay_injection_without_task() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_delay_injection(None, 5_000_000);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::ChaosInjection {
                kind, task, data, ..
            } => {
                assert_eq!(*kind, chaos_kind::DELAY);
                assert!(task.is_none());
                assert_eq!(*data, 5_000_000);
            }
            other => panic!("expected ChaosInjection, got {other:?}"),
        }
    }

    #[test]
    fn io_error_injection() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        recorder.record_io_error_injection(Some(make_task_id(5, 0)), 7);
        let trace = recorder.finish().expect("trace");
        match &trace.events[0] {
            ReplayEvent::ChaosInjection { kind, data, .. } => {
                assert_eq!(*kind, chaos_kind::IO_ERROR);
                assert_eq!(*data, 7);
            }
            other => panic!("expected ChaosInjection, got {other:?}"),
        }
    }

    // ── waker events when enabled ──────────────────────────────────

    #[test]
    fn waker_events_when_enabled() {
        let config = RecorderConfig::enabled().with_wakers(true);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_waker_wake(make_task_id(1, 0));
        recorder.record_waker_batch_wake(5);

        assert_eq!(recorder.event_count(), 2);
        let trace = recorder.finish().expect("trace");
        assert!(matches!(trace.events[0], ReplayEvent::WakerWake { .. }));
        assert!(matches!(
            trace.events[1],
            ReplayEvent::WakerBatchWake { count: 5 }
        ));
    }

    // ── config builders ────────────────────────────────────────────

    #[test]
    fn config_disabled_creates_disabled() {
        let config = RecorderConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn config_with_capacity() {
        let config = RecorderConfig::enabled().with_capacity(4096);
        assert_eq!(config.initial_capacity, 4096);
    }

    #[test]
    fn config_with_max_file_size() {
        let config = RecorderConfig::enabled().with_max_file_size(512 * 1024);
        assert_eq!(config.max_file_size, 512 * 1024);
    }

    #[test]
    fn config_with_max_memory() {
        let config = RecorderConfig::enabled().with_max_memory(50 * 1024 * 1024);
        assert_eq!(config.max_memory, 50 * 1024 * 1024);
    }

    // ── LimitAction Debug ──────────────────────────────────────────

    #[test]
    fn limit_action_debug_variants() {
        assert_eq!(format!("{:?}", LimitAction::StopRecording), "StopRecording");
        assert_eq!(format!("{:?}", LimitAction::DropOldest), "DropOldest");
        assert_eq!(format!("{:?}", LimitAction::Fail), "Fail");
        let cb = LimitAction::Callback(Arc::new(|_| LimitAction::StopRecording));
        assert_eq!(format!("{cb:?}"), "Callback(..)");
    }

    // ── LimitKind ──────────────────────────────────────────────────

    #[test]
    fn limit_kind_eq() {
        assert_eq!(LimitKind::MaxEvents, LimitKind::MaxEvents);
        assert_eq!(LimitKind::MaxMemory, LimitKind::MaxMemory);
        assert_eq!(LimitKind::MaxFileSize, LimitKind::MaxFileSize);
        assert_ne!(LimitKind::MaxEvents, LimitKind::MaxMemory);
    }

    // ── max_memory with drop_oldest ────────────────────────────────

    #[test]
    fn max_memory_drop_oldest() {
        let config = RecorderConfig::enabled()
            .with_max_memory(20)
            .on_limit(LimitAction::DropOldest);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        // Should have kept events but dropped oldest to fit memory
        let trace = recorder.finish().expect("trace");
        assert!(trace.events.len() <= 2);
    }

    // ── callback that returns DropOldest ────────────────────────────

    #[test]
    fn callback_returning_drop_oldest() {
        let action = LimitAction::Callback(Arc::new(|_| LimitAction::DropOldest));
        let config = RecorderConfig::enabled()
            .with_max_events(Some(2))
            .on_limit(action);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        recorder.record_task_scheduled(make_task_id(3, 0), 2);

        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.events.len(), 2);
        // Oldest should have been dropped
        match &trace.events[0] {
            ReplayEvent::TaskScheduled { at_tick, .. } => assert_eq!(*at_tick, 1),
            other => panic!("expected TaskScheduled, got {other:?}"),
        }
    }

    // ── estimated size tracks correctly ─────────────────────────────

    #[test]
    fn estimated_size_resets_after_take() {
        let mut recorder = TraceRecorder::new(TraceMetadata::new(42));
        for i in 0..50 {
            recorder.record_task_scheduled(make_task_id(i, 0), u64::from(i));
        }
        let size_before = recorder.estimated_size();
        assert!(size_before > 50);

        recorder.take();
        let size_after = recorder.estimated_size();
        assert!(size_after < size_before);
        assert_eq!(size_after, 50); // Just the base overhead
    }

    // ── chaos_kind constants ───────────────────────────────────────

    #[test]
    fn chaos_kind_constants_are_distinct() {
        let kinds = [
            chaos_kind::CANCEL,
            chaos_kind::DELAY,
            chaos_kind::IO_ERROR,
            chaos_kind::WAKEUP_STORM,
            chaos_kind::BUDGET_EXHAUST,
        ];
        let unique: std::collections::BTreeSet<_> = kinds.iter().collect();
        assert_eq!(unique.len(), kinds.len());
    }

    // ── finish metadata ────────────────────────────────────────────

    #[test]
    fn finish_preserves_metadata_seed() {
        let recorder = TraceRecorder::new(TraceMetadata::new(99));
        let trace = recorder.finish().expect("trace");
        assert_eq!(trace.metadata.seed, 99);
    }

    // ── stopped recorder ignores events ────────────────────────────

    #[test]
    fn stopped_recorder_ignores_events() {
        let config = RecorderConfig::enabled()
            .with_max_events(Some(1))
            .on_limit(LimitAction::StopRecording);
        let mut recorder = TraceRecorder::with_config(TraceMetadata::new(42), config);

        recorder.record_task_scheduled(make_task_id(1, 0), 0);
        // This triggers stop
        recorder.record_task_scheduled(make_task_id(2, 0), 1);
        // These should all be ignored
        recorder.record_rng_seed(42);
        recorder.record_time_advanced(Time::ZERO, Time::from_millis(1));
        recorder.record_io_ready(1, true, false, false, false);

        assert_eq!(recorder.event_count(), 1);
    }

    // ── default config values ──────────────────────────────────────

    #[test]
    fn default_config_values() {
        let config = RecorderConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.initial_capacity, 1024);
        assert!(config.record_rng);
        assert!(config.record_wakers);
        assert_eq!(config.max_events, None);
        assert_eq!(config.max_memory, DEFAULT_MAX_MEMORY);
        assert_eq!(config.max_file_size, DEFAULT_MAX_FILE_SIZE);
    }

    #[test]
    fn enabled_config_values() {
        let config = RecorderConfig::enabled();
        assert!(config.enabled);
        assert_eq!(config.initial_capacity, 1024);
        assert!(config.record_rng);
        assert!(config.record_wakers);
        assert_eq!(config.max_events, None);
        assert_eq!(config.max_memory, DEFAULT_MAX_MEMORY);
        assert_eq!(config.max_file_size, DEFAULT_MAX_FILE_SIZE);
    }
