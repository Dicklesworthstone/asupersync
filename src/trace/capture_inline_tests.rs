    use super::*;
    use crate::types::{RegionId, Time};

    fn ids() -> (TaskId, RegionId) {
        (TaskId::new_for_test(0, 1), RegionId::new_for_test(0, 1))
    }

    #[test]
    fn capture_receipt_accepts_completed_polls_and_reserved_sequence_gaps() {
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 2);
        let (task, region) = ids();
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        let _unused = trace.next_seq();
        recorder.record(Some(1), |seq| {
            TraceEvent::schedule(seq, Time::ZERO, task, region)
        });
        recorder.record(Some(1), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total_events(), 4);
        assert_eq!(snapshot.dropped_events(), 0);
        assert_eq!(snapshot.contexts().len(), 2);
        assert_eq!(snapshot.contexts()[1].worker_sequence, 1);
        assert_eq!(snapshot.contexts()[1].worker_id, Some(1));
        assert_eq!(snapshot.production_schedule().unwrap().summary().steps, 1);
    }

    #[test]
    fn capture_receipt_rejects_partial_runs_and_ring_eviction() {
        let trace = TraceBufferHandle::new(3);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        assert_eq!(
            recorder.snapshot().production_schedule().unwrap_err(),
            ScheduleCaptureError::UnfinishedTasks { count: 1 }
        );
        recorder.record(Some(0), |seq| {
            TraceEvent::yield_task(seq, Time::ZERO, task, region)
        });
        recorder.record(None, |seq| TraceEvent::wake(seq, Time::ZERO, task, region));
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total_events(), 5);
        assert_eq!(snapshot.dropped_events(), 2);
        assert!(snapshot.contexts().len() <= snapshot.capacity());
        assert_eq!(
            snapshot.production_schedule().unwrap_err(),
            ScheduleCaptureError::Truncated { dropped_events: 2 }
        );
    }

    #[test]
    fn capture_projection_leaves_out_block_on_caller_tasks() {
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        let caller = TaskId::new_for_test(1, 1);
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, caller, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        recorder.record(None, |seq| {
            TraceEvent::wake(seq, Time::ZERO, caller, region)
        });
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });

        // Unnoted, the caller's root looks like a scheduled task that never
        // finished: it is still inside block_on.
        let unnoted = recorder.snapshot();
        assert!(unnoted.caller_tasks().is_empty());
        assert_eq!(
            unnoted.production_schedule().unwrap_err(),
            ScheduleCaptureError::UnfinishedTasks { count: 1 }
        );

        // Noted, it is left out of the projection; a noted task without
        // retained observations is not reported.
        recorder.note_caller_task(caller);
        recorder.note_caller_task(TaskId::new_for_test(9, 1));
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.caller_tasks(), &[caller]);
        assert_eq!(snapshot.events().len(), 5);
        let schedule = snapshot.production_schedule().unwrap();
        assert_eq!(schedule.summary().spawned, 1);
        assert_eq!(schedule.summary().steps, 1);
        assert_eq!(
            schedule.spawn_order(),
            &[crate::trace::replay::CompactTaskId::from(task)]
        );
    }

    /// br-asupersync-bi2462.8: the kept terminal outcome reaches the
    /// projected completion, a caller task's outcome is left out, and a
    /// completion without a kept outcome is refused instead of reading as Ok.
    #[test]
    fn capture_projection_carries_terminal_outcomes_and_refuses_missing_ones() {
        use crate::trace::replay::ReplayEvent;
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        let caller = TaskId::new_for_test(1, 1);
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, caller, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        trace.record_completion_event(Severity::Cancelled, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        trace.record_completion_event(Severity::Panicked, |seq| {
            TraceEvent::complete(seq, Time::ZERO, caller, region)
        });
        recorder.note_caller_task(caller);
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.terminal_outcomes(), &[(task, Severity::Cancelled)]);
        let schedule = snapshot.production_schedule().unwrap();
        assert!(schedule.carries_outcomes());
        let compact = crate::trace::replay::CompactTaskId::from(task);
        assert_eq!(
            schedule.captured_outcome(compact),
            Some(Severity::Cancelled)
        );
        assert!(schedule.trace().events.iter().any(|event| matches!(
            event,
            ReplayEvent::TaskCompleted { task: completed, outcome: 2 } if *completed == compact
        )));

        // A Complete written without its outcome cannot be projected.
        let bare = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(bare.clone(), 1);
        bare.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        recorder.record(Some(0), |seq| {
            TraceEvent::poll(seq, Time::ZERO, task, region)
        });
        bare.record_event(|seq| TraceEvent::complete(seq, Time::ZERO, task, region));
        assert_eq!(
            recorder.snapshot().production_schedule().unwrap_err(),
            ScheduleCaptureError::MissingOutcome { seq: 2, task }
        );
        // A projection built from the trace alone claims no outcomes.
        let plain = ProductionSchedule::from_runtime_trace(recorder.snapshot().events()).unwrap();
        assert!(!plain.carries_outcomes());
        assert_eq!(plain.captured_outcome(compact), None);
    }

    #[test]
    fn capture_receipt_refuses_unbacked_poll_observations() {
        let trace = TraceBufferHandle::new(8);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::poll(seq, Time::ZERO, task, region));
        trace.record_completion_event(Severity::Ok, |seq| {
            TraceEvent::complete(seq, Time::ZERO, task, region)
        });
        assert_eq!(
            recorder.snapshot().production_schedule().unwrap_err(),
            ScheduleCaptureError::MissingSchedulerContext { seq: 1 }
        );
    }

    #[test]
    fn concurrent_capture_snapshot_keeps_counts_and_context_atomic() {
        let trace = TraceBufferHandle::new(7);
        let recorder = std::sync::Arc::new(ScheduleCaptureRecorder::new(trace.clone(), 2));
        let (task, region) = ids();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..256 {
                    trace.record_event(|seq| TraceEvent::user_trace(seq, Time::ZERO, "ordinary"));
                }
            });
            for worker in 0..2 {
                let recorder = recorder.clone();
                scope.spawn(move || {
                    for _ in 0..256 {
                        recorder.record(Some(worker), |seq| {
                            TraceEvent::poll(seq, Time::ZERO, task, region)
                        });
                    }
                });
            }
            for _ in 0..256 {
                let snapshot = recorder.snapshot();
                assert_eq!(
                    snapshot.total_events(),
                    snapshot.events().len() as u64 + snapshot.dropped_events()
                );
                // This source allocates no unused sequences. Even ordinary
                // producers must publish their count with their ring write.
                assert_eq!(
                    snapshot.total_events(),
                    snapshot.events().last().map_or(0, |event| event.seq + 1)
                );
                let scheduler_events: Vec<_> = snapshot
                    .events()
                    .iter()
                    .filter(|event| is_scheduler_observation(event.kind))
                    .collect();
                assert_eq!(snapshot.contexts().len(), scheduler_events.len());
                for (event, context) in scheduler_events.iter().zip(snapshot.contexts()) {
                    assert_eq!(event.seq, context.event_sequence);
                }
            }
        });
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total_events(), 768);
        assert_eq!(snapshot.dropped_events(), 761);
    }
