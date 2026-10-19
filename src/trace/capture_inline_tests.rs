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

    fn witnessed_request(
        trace: &TraceBufferHandle,
        task: TaskId,
        region: RegionId,
        reason: &CancelReason,
        budget: Budget,
    ) -> u64 {
        let start = trace.begin_cancellation_publication(task);
        let mut request_sequence = None;
        trace.record_event(|seq| {
            request_sequence = Some(seq);
            TraceEvent::cancel_request(seq, Time::ZERO, task, region, reason.clone())
        });
        trace.finish_cancellation_publication(start, request_sequence, Some(budget), false);
        request_sequence.unwrap()
    }

    fn captured_ack(
        recorder: &ScheduleCaptureRecorder,
        worker: usize,
        task: TaskId,
        region: RegionId,
        reason: &CancelReason,
    ) {
        recorder.record(Some(worker), |seq| {
            TraceEvent::new(
                seq,
                Time::ZERO,
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task,
                    region,
                    reason: reason.clone(),
                },
            )
        });
    }

    fn captured_poll(
        recorder: &ScheduleCaptureRecorder,
        worker: usize,
        task: TaskId,
        region: RegionId,
    ) {
        recorder.record(Some(worker), |seq| TraceEvent::poll(seq, Time::ZERO, task, region));
    }

    fn captured_yield(
        recorder: &ScheduleCaptureRecorder,
        worker: usize,
        task: TaskId,
        region: RegionId,
    ) {
        recorder.record(Some(worker), |seq| {
            TraceEvent::yield_task(seq, Time::ZERO, task, region)
        });
    }

    fn captured_completion(
        trace: &TraceBufferHandle,
        task: TaskId,
        region: RegionId,
        severity: Severity,
        reason: Option<&CancelReason>,
    ) {
        trace.record_completion_event_with_cancellation(
            severity,
            Some(crate::trace::buffer::TerminalCancellationState {
                requested: reason.is_some(),
                reason: reason.cloned(),
            }),
            |seq| TraceEvent::complete(seq, Time::ZERO, task, region),
        );
    }

    /// asupersync-bi2462.8: preserve attribution and the effective budget.
    /// The same task is repolled on worker 1 before worker 0 records its old
    /// acknowledgement, so latest-task-poll attribution would be incorrect.
    #[test]
    fn cancellation_capture_keeps_full_reason_budget_and_ack_poll_ordinals() {
        let trace = TraceBufferHandle::new(64);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 2);
        let (task, region) = ids();
        let other = TaskId::new_for_test(1, 1);
        let reason = CancelReason::user("witnessed cancellation")
            .with_region(region)
            .with_task(task)
            .with_cause(CancelReason::timeout());
        let budget = reason.cleanup_budget().with_poll_quota(7);
        assert_ne!(budget, reason.cleanup_budget());
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, other, region));
        captured_poll(&recorder, 0, task, region);
        captured_yield(&recorder, 0, task, region);
        let request_sequence = witnessed_request(&trace, task, region, &reason, budget);
        captured_poll(&recorder, 0, task, region);
        captured_yield(&recorder, 0, task, region);
        captured_poll(&recorder, 1, task, region);
        captured_yield(&recorder, 1, task, region);
        captured_ack(&recorder, 0, task, region, &reason);
        captured_ack(&recorder, 1, task, region, &reason);
        captured_poll(&recorder, 1, other, region);
        captured_yield(&recorder, 1, other, region);
        captured_poll(&recorder, 0, task, region);
        captured_ack(&recorder, 0, task, region, &reason);
        captured_completion(&trace, task, region, Severity::Cancelled, Some(&reason));
        captured_poll(&recorder, 1, other, region);
        captured_completion(&trace, other, region, Severity::Ok, None);

        let snapshot = recorder.snapshot();
        assert!(snapshot.production_schedule().unwrap().cancellation_events().is_none());
        let schedule = snapshot.production_schedule_with_cancellation().unwrap();
        let events = schedule.cancellation_events().unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].phase(), ProductionCancellationPhase::Request);
        assert_eq!(events[0].source_sequence(), request_sequence);
        assert_eq!(events[0].after_dispatches(), 1);
        assert_eq!(events[0].task_poll_ordinal(), 1);
        assert_eq!(events[1].phase(), ProductionCancellationPhase::Acknowledgement);
        assert_eq!(events[1].after_dispatches(), 3);
        assert_eq!(events[1].task_poll_ordinal(), 2);
        assert_eq!(events[2].after_dispatches(), 3);
        assert_eq!(events[2].task_poll_ordinal(), 3);
        assert_eq!(events[3].after_dispatches(), 5);
        assert_eq!(events[3].task_poll_ordinal(), 4);
        for event in events {
            assert_eq!(event.task(), CompactTaskId::from(task));
            assert_eq!(event.region(), CompactRegionId::from(region));
            assert_eq!(event.reason(), &reason);
            assert_eq!(event.cleanup_budget(), budget);
        }
    }

    /// A flag can be published, observed by an entire poll, and only then
    /// traced. The canonical Request itself is between polls in this witness;
    /// only the publication span exposes why injecting there would be wrong.
    #[test]
    fn cancellation_capture_refuses_polls_hidden_before_the_request_trace() {
        for polling_target in [true, false] {
            let trace = TraceBufferHandle::new(32);
            let recorder = ScheduleCaptureRecorder::new(trace.clone(), 2);
            let (task, region) = ids();
            let other = TaskId::new_for_test(1, 1);
            let polling_task = if polling_target { task } else { other };
            let reason = CancelReason::user("publication overlap");
            trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
            if !polling_target {
                trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, other, region));
            }
            let start = trace.begin_cancellation_publication(task);
            captured_poll(&recorder, 1, polling_task, region);
            captured_yield(&recorder, 1, polling_task, region);
            let mut request_sequence = None;
            trace.record_event(|seq| {
                request_sequence = Some(seq);
                TraceEvent::cancel_request(seq, Time::ZERO, task, region, reason.clone())
            });
            trace.finish_cancellation_publication(
                start,
                request_sequence,
                Some(reason.cleanup_budget()),
                false,
            );
            captured_poll(&recorder, 0, task, region);
            captured_ack(&recorder, 0, task, region, &reason);
            captured_completion(&trace, task, region, Severity::Cancelled, Some(&reason));
            if !polling_target {
                captured_poll(&recorder, 1, other, region);
                captured_completion(&trace, other, region, Severity::Ok, None);
            }
            let snapshot = recorder.snapshot();
            assert!(snapshot.production_schedule().is_ok());
            assert_eq!(
                snapshot.production_schedule_with_cancellation().unwrap_err(),
                ScheduleCaptureError::CancellationDuringPoll {
                    seq: request_sequence.unwrap(),
                    task,
                    polling_task,
                }
            );
        }
    }

    #[test]
    fn cancellation_capture_refuses_missing_provenance_and_reason_drift() {
        for case in 0..4 {
            let trace = TraceBufferHandle::new(16);
            let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
            let (task, region) = ids();
            let reason = CancelReason::user("source request");
            trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
            if case == 0 {
                // A bare canonical event has no evidence of flag publication.
                trace.record_event(|seq| {
                    TraceEvent::cancel_request(seq, Time::ZERO, task, region, reason.clone())
                });
            } else if case == 3 {
                witnessed_request(&trace, task, region, &reason, reason.cleanup_budget());
            }
            captured_poll(&recorder, 0, task, region);
            if case != 2 {
                let acknowledged = if case == 3 {
                    reason.clone().with_message("unrecorded strengthening")
                } else {
                    reason.clone()
                };
                captured_ack(&recorder, 0, task, region, &acknowledged);
            }
            captured_completion(&trace, task, region, Severity::Cancelled, Some(&reason));
            let snapshot = recorder.snapshot();
            assert!(snapshot.production_schedule().is_ok());
            let error = snapshot.production_schedule_with_cancellation().unwrap_err();
            match case {
                0 => assert!(matches!(error, ScheduleCaptureError::CancellationPublication { .. })),
                1 | 2 => assert!(matches!(error, ScheduleCaptureError::MissingCancellationRequest { .. })),
                3 => assert!(matches!(error, ScheduleCaptureError::CancellationOrder { .. })),
                _ => unreachable!(),
            }
        }
    }

    /// An acknowledgement recorded after a later between-poll request cannot
    /// be moved back across that request and called the same causal history.
    #[test]
    fn cancellation_capture_refuses_acknowledgement_crossing_a_later_request() {
        let trace = TraceBufferHandle::new(32);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        let other = TaskId::new_for_test(1, 1);
        let reason = CancelReason::user("ordered cancellation");
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, other, region));
        witnessed_request(&trace, task, region, &reason, reason.cleanup_budget());
        captured_poll(&recorder, 0, task, region);
        captured_yield(&recorder, 0, task, region);
        witnessed_request(&trace, other, region, &reason, reason.cleanup_budget());
        captured_ack(&recorder, 0, task, region, &reason);
        captured_completion(&trace, task, region, Severity::Cancelled, Some(&reason));
        captured_poll(&recorder, 0, other, region);
        captured_ack(&recorder, 0, other, region, &reason);
        captured_completion(&trace, other, region, Severity::Cancelled, Some(&reason));
        let error = recorder
            .snapshot()
            .production_schedule_with_cancellation()
            .unwrap_err();
        assert!(matches!(
            error,
            ScheduleCaptureError::CancellationOrder {
                reason: "cancellation observations invert their originating poll boundaries",
                ..
            }
        ));
    }

    #[test]
    fn cancellation_capture_refuses_unfinished_strengthened_and_evicted_publications() {
        for case in 0..3 {
            let trace = TraceBufferHandle::new(8);
            let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
            let (task, region) = ids();
            trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
            if case == 2 {
                for _ in 0..9 {
                    let _ = trace.begin_cancellation_publication(task);
                }
            } else {
                let start = trace.begin_cancellation_publication(task);
                if case == 1 {
                    trace.finish_cancellation_publication(start, None, None, true);
                }
            }
            captured_poll(&recorder, 0, task, region);
            captured_completion(&trace, task, region, Severity::Ok, None);
            let snapshot = recorder.snapshot();
            assert_eq!(snapshot.dropped_events(), 0);
            assert!(snapshot.cancellation_publications.spans.len() <= snapshot.capacity());
            let error = snapshot.production_schedule_with_cancellation().unwrap_err();
            if case == 2 {
                assert_eq!(
                    error,
                    ScheduleCaptureError::CancellationWitnessesTruncated { dropped_spans: 1 }
                );
            } else {
                assert!(matches!(error, ScheduleCaptureError::CancellationPublication { .. }));
            }
        }
    }

    #[test]
    fn cancellation_capture_noop_and_disabled_publishers_do_not_create_evidence() {
        let trace = TraceBufferHandle::new(8);
        let (task, region) = ids();
        assert_eq!(trace.begin_cancellation_publication(task), None);
        trace.finish_cancellation_publication(None, None, None, true);
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        assert_eq!(trace.snapshot()[0].seq, 0);

        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        for _ in 0..32 {
            let start = trace.begin_cancellation_publication(task);
            trace.finish_cancellation_publication(start, None, None, false);
        }
        captured_poll(&recorder, 0, task, region);
        captured_completion(&trace, task, region, Severity::Ok, None);
        let snapshot = recorder.snapshot();
        assert!(snapshot.cancellation_publications.spans.is_empty());
        assert_eq!(snapshot.cancellation_publications.dropped_spans, 0);
        let schedule = snapshot.production_schedule_with_cancellation().unwrap();
        assert!(schedule.cancellation_events().unwrap().is_empty());
    }

    #[test]
    fn cancellation_capture_excludes_caller_cancellation_as_harness_input() {
        let trace = TraceBufferHandle::new(16);
        let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
        let (task, region) = ids();
        let caller = TaskId::new_for_test(1, 1);
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
        trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, caller, region));
        recorder.note_caller_task(caller);
        trace.record_event(|seq| {
            TraceEvent::cancel_request(
                seq,
                Time::ZERO,
                caller,
                region,
                CancelReason::user("external caller cancellation"),
            )
        });
        captured_poll(&recorder, 0, task, region);
        captured_completion(&trace, task, region, Severity::Ok, None);
        let schedule = recorder
            .snapshot()
            .production_schedule_with_cancellation()
            .unwrap();
        assert_eq!(schedule.spawn_order(), &[CompactTaskId::from(task)]);
        assert!(schedule.cancellation_events().unwrap().is_empty());
    }

    /// An Ok outcome without a checkpoint is not evidence that no cancellation
    /// happened. The terminal authoritative Cx witness must match a supported
    /// request, including its full reason; missing evidence fails closed.
    #[test]
    fn cancellation_capture_checks_silent_terminal_cx_state() {
        for case in 0..6 {
            let trace = TraceBufferHandle::new(16);
            let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
            let (task, region) = ids();
            let reason = CancelReason::user("silent source cancellation");
            trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
            if (1..5).contains(&case) {
                witnessed_request(&trace, task, region, &reason, reason.cleanup_budget());
            }
            captured_poll(&recorder, 0, task, region);
            let cancellation = match case {
                0 | 1 => Some(crate::trace::buffer::TerminalCancellationState {
                    requested: true,
                    reason: Some(reason.clone()),
                }),
                2 => Some(crate::trace::buffer::TerminalCancellationState {
                    requested: true,
                    reason: None,
                }),
                3 => Some(crate::trace::buffer::TerminalCancellationState {
                    requested: true,
                    reason: Some(reason.clone().with_message("silent reason drift")),
                }),
                4 => Some(crate::trace::buffer::TerminalCancellationState {
                    requested: false,
                    reason: None,
                }),
                _ => None,
            };
            trace.record_completion_event_with_cancellation(
                Severity::Ok,
                cancellation,
                |seq| TraceEvent::complete(seq, Time::ZERO, task, region),
            );
            let snapshot = recorder.snapshot();
            assert!(snapshot.production_schedule().is_ok());
            let result = snapshot.production_schedule_with_cancellation();
            if case == 1 {
                let schedule = result.unwrap();
                let events = schedule.cancellation_events().unwrap();
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].phase(), ProductionCancellationPhase::Request);
            } else {
                let error = result.unwrap_err();
                match case {
                    0 => assert!(matches!(
                        error,
                        ScheduleCaptureError::MissingCancellationRequest { .. }
                    )),
                    2..=4 => assert!(matches!(
                        error,
                        ScheduleCaptureError::CancellationOrder { .. }
                    )),
                    5 => assert!(matches!(
                        error,
                        ScheduleCaptureError::CancellationPublication { .. }
                    )),
                    _ => unreachable!(),
                }
            }
        }
    }
