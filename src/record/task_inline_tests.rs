    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::error::{Error, ErrorKind};
    use crate::types::task_context::CancelWaker;
    use crate::util::ArenaIndex;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 0))
    }

    fn region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn request_cancel(record: &mut TaskRecord, reason: CancelReason) -> bool {
        let (newly_cancelled, wakes) = record.request_cancel(reason).into_parts();
        wakes.dispatch();
        newly_cancelled
    }

    fn request_cancel_with_budget(
        record: &mut TaskRecord,
        reason: CancelReason,
        budget: Budget,
    ) -> bool {
        let (newly_cancelled, wakes) = record
            .request_cancel_with_budget(reason, budget)
            .into_parts();
        wakes.dispatch();
        newly_cancelled
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn cancellation_trace_reenters_only_after_outer_lock_and_contains_panic() {
        use tracing_subscriber::prelude::*;

        struct PanickingLayer {
            attempts: Arc<AtomicUsize>,
            reentries: Arc<AtomicUsize>,
            outer_lock: Arc<parking_lot::Mutex<()>>,
        }

        impl<S> tracing_subscriber::Layer<S> for PanickingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if self.outer_lock.try_lock().is_some() {
                    self.reentries.fetch_add(1, Ordering::SeqCst);
                }
                panic!("adversarial cancellation tracing subscriber");
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let reentries = Arc::new(AtomicUsize::new(0));
        let outer_lock = Arc::new(parking_lot::Mutex::new(()));
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        let subscriber = tracing_subscriber::registry().with(PanickingLayer {
            attempts: Arc::clone(&attempts),
            reentries: Arc::clone(&reentries),
            outer_lock: Arc::clone(&outer_lock),
        });

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::subscriber::with_default(subscriber, || {
                let effects = {
                    let _outer_guard = outer_lock.lock();
                    let effects = record
                        .request_cancel_with_budget(CancelReason::shutdown(), Budget::INFINITE);
                    assert_eq!(
                        attempts.load(Ordering::SeqCst),
                        0,
                        "request_cancel must not enter the subscriber under the outer lock"
                    );
                    effects
                };

                let (newly_cancelled, observers_and_wakes) = effects.into_parts();
                assert!(newly_cancelled);
                observers_and_wakes.dispatch();
                assert_eq!(attempts.load(Ordering::SeqCst), 1);
                assert_eq!(reentries.load(Ordering::SeqCst), 1);
            });
        }));

        assert!(result.is_ok(), "subscriber panic must not escape dispatch");
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn unpublished_cancel_trace_waits_for_admission_publication_callback() {
        use tracing_subscriber::prelude::*;

        struct PanickingLayer {
            attempts: Arc<AtomicUsize>,
            early_attempts: Arc<AtomicUsize>,
            lane_published: Arc<std::sync::atomic::AtomicBool>,
        }

        impl<S> tracing_subscriber::Layer<S> for PanickingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if !self.lane_published.load(Ordering::SeqCst) {
                    self.early_attempts.fetch_add(1, Ordering::SeqCst);
                }
                panic!("adversarial pre-publication tracing subscriber");
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let early_attempts = Arc::new(AtomicUsize::new(0));
        let lane_published = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        inner.write().runnable_publication = RunnablePublication::Unpublished;
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));
        let subscriber = tracing_subscriber::registry().with(PanickingLayer {
            attempts: Arc::clone(&attempts),
            early_attempts: Arc::clone(&early_attempts),
            lane_published: Arc::clone(&lane_published),
        });

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::subscriber::with_default(subscriber, || {
                let effects = record.request_cancel_with_budget(
                    CancelReason::user("prepublication"),
                    Budget::INFINITE,
                );
                let (newly_cancelled, immediate_effects) = effects.into_parts();
                assert!(newly_cancelled);
                immediate_effects.dispatch();
                assert_eq!(attempts.load(Ordering::SeqCst), 0);

                let repeated =
                    record.request_cancel_with_budget(CancelReason::shutdown(), Budget::INFINITE);
                let (newly_cancelled, repeated_effects) = repeated.into_parts();
                assert!(!newly_cancelled);
                repeated_effects.dispatch();
                assert_eq!(
                    attempts.load(Ordering::SeqCst),
                    0,
                    "prepublication strengthening traces remain coalesced"
                );
                assert!(
                    record
                        .cancel_reason()
                        .is_some_and(|reason| reason.is_kind(crate::types::CancelKind::Shutdown)),
                    "strongest prepublication reason remains authoritative"
                );

                let deferred = crate::runtime::task_handle::publish_admitted_cancel_state(
                    &inner,
                    None,
                    |priority| {
                        assert!(
                            priority.is_some(),
                            "cancelled admission selects cancel lane"
                        );
                        lane_published.store(true, Ordering::SeqCst);
                    },
                );
                assert_eq!(attempts.load(Ordering::SeqCst), 0);
                assert!(inner.read().runnable_publication.is_published());
                deferred.dispatch();
            });
        }));

        assert!(result.is_ok(), "subscriber panic must not escape dispatch");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(early_attempts.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn terminal_retirement_suppresses_unpublished_cancel_trace() {
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        inner.write().runnable_publication = RunnablePublication::Unpublished;
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));

        let (newly_cancelled, immediate_effects) = record
            .request_cancel_with_budget(CancelReason::shutdown(), Budget::INFINITE)
            .into_parts();
        assert!(newly_cancelled);
        immediate_effects.dispatch();
        assert!(
            inner.read().pending_task_cancel_trace.is_some(),
            "unpublished cancellation retains one bounded trace receipt"
        );

        let retired_wakers = {
            let mut guard = inner.write();
            let retired_wakers = guard.take_cancel_wakers();
            assert!(
                guard.pending_task_cancel_trace.is_none(),
                "terminal retirement suppresses a receipt with no physical lane"
            );
            retired_wakers
        };
        drop(retired_wakers);
    }

    fn scrub_task_record_ids(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(task_id) = scrubbed.pointer_mut("/task_id") {
            *task_id = json!("[TASK_ID]");
        }

        if let Some(region_id) = scrubbed.pointer_mut("/region_id") {
            *region_id = json!("[REGION_ID]");
        }

        if let Some(origin_region) = scrubbed.pointer_mut("/reason/origin_region") {
            *origin_region = json!("[REGION_ID]");
        }

        if let Some(origin_task) = scrubbed.pointer_mut("/reason/origin_task") {
            *origin_task = json!("[TASK_ID]");
        }

        scrubbed
    }

    #[test]
    fn task_phase_transitions_are_atomic() {
        init_test("task_phase_transitions_are_atomic");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        crate::assert_with_log!(
            t.phase() == TaskPhase::Created,
            "phase created",
            TaskPhase::Created,
            t.phase()
        );

        let started = t.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Running,
            "phase running",
            TaskPhase::Running,
            t.phase()
        );

        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        crate::assert_with_log!(
            t.phase() == TaskPhase::CancelRequested,
            "phase cancel requested",
            TaskPhase::CancelRequested,
            t.phase()
        );

        let ack = t.acknowledge_cancel();
        crate::assert_with_log!(ack.is_some(), "acknowledge_cancel", true, ack.is_some());
        crate::assert_with_log!(
            t.phase() == TaskPhase::Cancelling,
            "phase cancelling",
            TaskPhase::Cancelling,
            t.phase()
        );

        let cleaned = t.cleanup_done();
        crate::assert_with_log!(cleaned, "cleanup_done", true, cleaned);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Finalizing,
            "phase finalizing",
            TaskPhase::Finalizing,
            t.phase()
        );

        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        crate::assert_with_log!(
            t.phase() == TaskPhase::Completed,
            "phase completed",
            TaskPhase::Completed,
            t.phase()
        );

        crate::test_complete!("task_phase_transitions_are_atomic");
    }

    #[test]
    fn wake_state_dedups_across_threads() {
        init_test("wake_state_dedups_across_threads");
        let state = Arc::new(TaskWakeState::new());
        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let state = Arc::clone(&state);
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if state.notify() {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }

        let count = successes.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "single notify wins", 1usize, count);
        let notified = state.is_notified();
        crate::assert_with_log!(notified, "notified true", true, notified);
        state.clear();
        let cleared = state.is_notified();
        crate::assert_with_log!(!cleared, "notified cleared", false, cleared);
        crate::test_complete!("wake_state_dedups_across_threads");
    }

    #[test]
    fn wake_state_tracks_wake_during_poll() {
        init_test("wake_state_tracks_wake_during_poll");
        let state = TaskWakeState::new();

        state.begin_poll();
        let woken = state.finish_poll();
        crate::assert_with_log!(!woken, "no wake during poll", false, woken);

        state.begin_poll();
        let scheduled = state.notify();
        crate::assert_with_log!(
            !scheduled,
            "wake during poll does not schedule",
            false,
            scheduled
        );
        let woken = state.finish_poll();
        crate::assert_with_log!(woken, "wake observed after poll", true, woken);
        let pending = state.is_notified();
        crate::assert_with_log!(pending, "pending wake recorded", true, pending);
        state.clear();
        let cleared = state.is_notified();
        crate::assert_with_log!(!cleared, "wake cleared", false, cleared);
        crate::test_complete!("wake_state_tracks_wake_during_poll");
    }

    #[test]
    fn cancel_before_first_poll_enters_cancel_requested() {
        init_test("cancel_before_first_poll_enters_cancel_requested");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let created = matches!(t.state, TaskState::Created);
        crate::assert_with_log!(created, "created", true, created);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        match &t.state {
            TaskState::CancelRequested {
                reason,
                cleanup_budget: _,
            } => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "reason kind",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_before_first_poll_enters_cancel_requested");
    }

    #[test]
    fn cancel_strengthens_idempotently_when_already_cancel_requested() {
        init_test("cancel_strengthens_idempotently_when_already_cancel_requested");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let first = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(first, "first cancel", true, first);
        let second = request_cancel(&mut t, CancelReason::shutdown());
        crate::assert_with_log!(!second, "second cancel false", false, second);
        match &t.state {
            TaskState::CancelRequested { reason, .. } => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Shutdown,
                    "reason kind",
                    crate::types::CancelKind::Shutdown,
                    reason.kind
                );
            }
            other => panic!("expected CancelRequested, got {other:?}"),
        }
        crate::test_complete!("cancel_strengthens_idempotently_when_already_cancel_requested");
    }

    #[test]
    fn completed_is_absorbing() {
        init_test("completed_is_absorbing");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(!requested, "request_cancel false", false, requested);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        match &t.state {
            TaskState::Completed(outcome) => {
                let ok = matches!(outcome, Outcome::Ok(()));
                crate::assert_with_log!(ok, "outcome ok", true, ok);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        crate::test_complete!("completed_is_absorbing");
    }

    #[test]
    fn can_be_polled_matches_state() {
        init_test("can_be_polled_matches_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(!can_poll, "not pollable", false, can_poll);
        let started = t.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(can_poll, "pollable", true, can_poll);

        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel_with_budget(&mut t, CancelReason::timeout(), Budget::INFINITE);
        let can_poll = t.state.can_be_polled();
        crate::assert_with_log!(can_poll, "pollable after cancel", true, can_poll);
        crate::test_complete!("can_be_polled_matches_state");
    }

    #[test]
    fn complete_with_error_outcome() {
        init_test("complete_with_error_outcome");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let err = Error::new(ErrorKind::User);
        let completed = t.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        crate::test_complete!("complete_with_error_outcome");
    }

    #[test]
    fn complete_cancelled_without_prior_request_still_emits_witness() {
        init_test("complete_cancelled_without_prior_request_still_emits_witness");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = t.start_running();

        let completed = t.complete(Outcome::Cancelled(CancelReason::timeout()));
        crate::assert_with_log!(completed, "complete cancelled", true, completed);

        let witness = t.cancel_witness().expect("completed cancel witness");
        crate::assert_with_log!(witness.epoch == 1, "epoch initialized", 1, witness.epoch);
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        CancelWitness::validate_transition(None, &witness)
            .expect("terminal cancelled witness is self-consistent");

        crate::test_complete!("complete_cancelled_without_prior_request_still_emits_witness");
    }

    #[test]
    fn complete_ok_after_cancel_request_becomes_cancelled() {
        init_test("complete_ok_after_cancel_request_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);

        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);

        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "cancel reason preserved",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }

        let witness = t
            .cancel_witness()
            .expect("cancel witness after coerced completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_ok_after_cancel_request_becomes_cancelled");
    }

    #[test]
    fn complete_err_after_cancel_request_becomes_cancelled() {
        init_test("complete_err_after_cancel_request_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let requested = request_cancel(&mut t, CancelReason::timeout());
        crate::assert_with_log!(requested, "request_cancel", true, requested);

        let err = Error::new(ErrorKind::User);
        let completed = t.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);

        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "cancel reason preserved",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }

        let witness = t
            .cancel_witness()
            .expect("cancel witness after coerced completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_err_after_cancel_request_becomes_cancelled");
    }

    #[test]
    fn complete_ok_during_cancellation_cleanup_becomes_cancelled() {
        init_test("complete_ok_during_cancellation_cleanup_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();

        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "completed cancelled", true, cancelled);

        let witness = t
            .cancel_witness()
            .expect("cancel witness during cleanup completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_ok_during_cancellation_cleanup_becomes_cancelled");
    }

    #[test]
    fn complete_cancelled_during_protocol_does_not_weaken_reason() {
        init_test("complete_cancelled_during_protocol_does_not_weaken_reason");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());

        let completed = t.complete(Outcome::Cancelled(CancelReason::user("soft")));
        crate::assert_with_log!(completed, "complete cancelled", true, completed);

        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "cancel reason stayed strongest",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }

        let witness = t.cancel_witness().expect("cancel witness after completion");
        crate::assert_with_log!(
            witness.reason.kind == crate::types::CancelKind::Timeout,
            "witness reason stayed strongest",
            crate::types::CancelKind::Timeout,
            witness.reason.kind
        );

        crate::test_complete!("complete_cancelled_during_protocol_does_not_weaken_reason");
    }

    #[test]
    fn complete_ok_during_finalization_becomes_cancelled() {
        init_test("complete_ok_during_finalization_becomes_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();

        let completed = t.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "completed cancelled", true, cancelled);

        let witness = t
            .cancel_witness()
            .expect("cancel witness during finalization completion");
        crate::assert_with_log!(
            witness.phase == CancelPhase::Completed,
            "phase completed",
            CancelPhase::Completed,
            witness.phase
        );
        crate::test_complete!("complete_ok_during_finalization_becomes_cancelled");
    }

    #[test]
    fn acknowledge_cancel_transitions_to_cancelling() {
        init_test("acknowledge_cancel_transitions_to_cancelling");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());

        let reason = t.acknowledge_cancel();
        let has_reason = reason.is_some();
        crate::assert_with_log!(has_reason, "reason present", true, has_reason);
        let kind = reason.unwrap().kind;
        crate::assert_with_log!(
            kind == crate::types::CancelKind::Timeout,
            "reason kind",
            crate::types::CancelKind::Timeout,
            kind
        );
        let cancelling = matches!(
            t.state,
            TaskState::Cancelling {
                reason: CancelReason {
                    kind: crate::types::CancelKind::Timeout,
                    ..
                },
                ..
            }
        );
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);
        crate::test_complete!("acknowledge_cancel_transitions_to_cancelling");
    }

    #[test]
    fn acknowledge_cancel_fails_for_wrong_state() {
        init_test("acknowledge_cancel_fails_for_wrong_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let none = t.acknowledge_cancel().is_none();
        crate::assert_with_log!(none, "none in created", true, none);

        // Move to Running
        t.start_running();
        let none = t.acknowledge_cancel().is_none();
        crate::assert_with_log!(none, "none in running", true, none);
        crate::test_complete!("acknowledge_cancel_fails_for_wrong_state");
    }

    #[test]
    fn cleanup_done_transitions_to_finalizing() {
        init_test("cleanup_done_transitions_to_finalizing");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();

        let cancelling = matches!(t.state, TaskState::Cancelling { .. });
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(cleanup, "cleanup_done", true, cleanup);
        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);
        crate::test_complete!("cleanup_done_transitions_to_finalizing");
    }

    #[test]
    fn cleanup_done_fails_for_wrong_state() {
        init_test("cleanup_done_fails_for_wrong_state");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(!cleanup, "cleanup_done false", false, cleanup);

        let _ = request_cancel(&mut t, CancelReason::timeout());
        // Still in CancelRequested, not Cancelling
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(!cleanup, "cleanup_done false", false, cleanup);
        crate::test_complete!("cleanup_done_fails_for_wrong_state");
    }

    #[test]
    fn finalize_done_transitions_to_completed_cancelled() {
        init_test("finalize_done_transitions_to_completed_cancelled");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();

        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);
        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        match &t.state {
            TaskState::Completed(Outcome::Cancelled(reason)) => {
                crate::assert_with_log!(
                    reason.kind == crate::types::CancelKind::Timeout,
                    "reason kind",
                    crate::types::CancelKind::Timeout,
                    reason.kind
                );
            }
            other => panic!("expected Completed(Cancelled), got {other:?}"),
        }
        crate::test_complete!("finalize_done_transitions_to_completed_cancelled");
    }

    #[test]
    fn full_cancellation_protocol_flow() {
        init_test("full_cancellation_protocol_flow");
        // Complete flow: Created → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let created = matches!(t.state, TaskState::Created);
        crate::assert_with_log!(created, "created", true, created);

        // Step 1: Request cancellation
        let requested = request_cancel(&mut t, CancelReason::user("stop"));
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        let requested_state = matches!(t.state, TaskState::CancelRequested { .. });
        crate::assert_with_log!(
            requested_state,
            "state cancel requested",
            true,
            requested_state
        );
        let cancelling = t.state.is_cancelling();
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);

        // Step 2: Acknowledge cancellation (checkpoint with mask=0)
        let reason = t.acknowledge_cancel().expect("should acknowledge");
        crate::assert_with_log!(
            reason.kind == crate::types::CancelKind::User,
            "reason kind",
            crate::types::CancelKind::User,
            reason.kind
        );
        let cancelling = matches!(t.state, TaskState::Cancelling { .. });
        crate::assert_with_log!(cancelling, "state cancelling", true, cancelling);

        // Step 3: Cleanup completes
        let cleanup = t.cleanup_done();
        crate::assert_with_log!(cleanup, "cleanup_done", true, cleanup);
        let finalizing = matches!(t.state, TaskState::Finalizing { .. });
        crate::assert_with_log!(finalizing, "state finalizing", true, finalizing);

        // Step 4: Finalizers complete
        let finalized = t.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        let terminal = t.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        let cancelled = matches!(t.state, TaskState::Completed(Outcome::Cancelled(_)));
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);
        crate::test_complete!("full_cancellation_protocol_flow");
    }

    #[test]
    fn cancellation_witness_sequence_is_monotone() {
        init_test("cancellation_witness_sequence_is_monotone");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        t.start_running();

        let _ = request_cancel(&mut t, CancelReason::timeout());
        let w1 = t.cancel_witness().expect("requested witness");

        let _ = t.acknowledge_cancel();
        let w2 = t.cancel_witness().expect("cancelling witness");
        CancelWitness::validate_transition(Some(&w1), &w2).expect("requested -> cancelling");

        let _ = t.cleanup_done();
        let w3 = t.cancel_witness().expect("finalizing witness");
        CancelWitness::validate_transition(Some(&w2), &w3).expect("cancelling -> finalizing");

        let w4 = t.finalize_done_with_witness().expect("completed witness");
        CancelWitness::validate_transition(Some(&w3), &w4).expect("finalizing -> completed");

        crate::test_complete!("cancellation_witness_sequence_is_monotone");
    }

    #[test]
    fn cancellation_witness_idempotent_requests() {
        init_test("cancellation_witness_idempotent_requests");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        t.start_running();

        let _ = request_cancel(&mut t, CancelReason::timeout());
        let w1 = t.cancel_witness().expect("first witness");

        let _ = request_cancel(&mut t, CancelReason::shutdown());
        let w2 = t.cancel_witness().expect("second witness");

        crate::assert_with_log!(w1.epoch == w2.epoch, "epoch stable", w1.epoch, w2.epoch);
        CancelWitness::validate_transition(Some(&w1), &w2).expect("idempotent request transition");

        crate::test_complete!("cancellation_witness_idempotent_requests");
    }

    #[test]
    fn cancellation_witness_rejects_out_of_order() {
        init_test("cancellation_witness_rejects_out_of_order");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        t.start_running();
        let _ = request_cancel(&mut t, CancelReason::timeout());
        let requested = t.cancel_witness().expect("requested witness");
        let _ = t.acknowledge_cancel();
        let _ = t.cleanup_done();
        let completed = t.finalize_done_with_witness().expect("completed witness");

        let err = CancelWitness::validate_transition(Some(&completed), &requested).err();
        crate::assert_with_log!(err.is_some(), "out of order rejected", true, err.is_some());

        crate::test_complete!("cancellation_witness_rejects_out_of_order");
    }

    #[test]
    fn linking_a_context_caches_its_budget_priority() {
        init_test("linking_a_context_caches_its_budget_priority");
        let budget = Budget::INFINITE.with_priority(200);
        let mut t = TaskRecord::new(task(), region(), budget);
        let inner = Arc::new(RwLock::new(CxInner::new(region(), task(), budget)));
        t.set_cx_inner(inner);
        crate::assert_with_log!(
            t.sched_priority == 200,
            "sched_priority",
            200,
            t.sched_priority
        );
        crate::test_complete!("linking_a_context_caches_its_budget_priority");
    }

    #[test]
    fn masking_operations() {
        init_test("masking_operations");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);

        // Need to set inner for mask operations to work
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner);

        let mask1 = t.increment_mask();
        crate::assert_with_log!(mask1 == 1, "mask 1", 1, mask1);
        let mask2 = t.increment_mask();
        crate::assert_with_log!(mask2 == 2, "mask 2", 2, mask2);

        let dec1 = t.decrement_mask();
        crate::assert_with_log!(dec1 == Some(1), "dec 1", Some(1), dec1);
        let dec0 = t.decrement_mask();
        crate::assert_with_log!(dec0 == Some(0), "dec 0", Some(0), dec0);

        // Can't go below zero
        let dec_none = t.decrement_mask();
        crate::assert_with_log!(dec_none.is_none(), "dec none", true, dec_none.is_none());
        crate::test_complete!("masking_operations");
    }

    #[test]
    fn cleanup_budget_accessor() {
        init_test("cleanup_budget_accessor");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let none = t.cleanup_budget().is_none();
        crate::assert_with_log!(none, "no budget", true, none);

        let _ = request_cancel_with_budget(
            &mut t,
            CancelReason::timeout(),
            Budget::new().with_poll_quota(500),
        );
        let budget = t.cleanup_budget().expect("should have cleanup budget");
        crate::assert_with_log!(
            budget.poll_quota == 500,
            "poll_quota",
            500,
            budget.poll_quota
        );
        crate::test_complete!("cleanup_budget_accessor");
    }

    #[test]
    fn request_cancel_updates_shared_cx() {
        init_test("request_cancel_updates_shared_cx");
        let mut t = TaskRecord::new(task(), region(), Budget::INFINITE);
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        t.set_cx_inner(inner.clone());
        let cx: crate::cx::Cx = crate::cx::Cx::from_inner(Arc::clone(&inner));

        let cancel_requested = inner.read().cancel_requested;
        crate::assert_with_log!(
            !cancel_requested,
            "cancel_requested false",
            false,
            cancel_requested
        );
        let cancel_reason_none = inner.read().cancel_reason.is_none();
        crate::assert_with_log!(
            cancel_reason_none,
            "cancel_reason none",
            true,
            cancel_reason_none
        );

        let _ = request_cancel(&mut t, CancelReason::timeout());

        let cancel_requested = inner.read().cancel_requested;
        crate::assert_with_log!(
            cancel_requested,
            "cancel_requested true",
            true,
            cancel_requested
        );
        crate::assert_with_log!(
            cx.is_cancel_requested(),
            "TaskRecord cancellation publishes through the linked Cx envelope",
            true,
            cx.is_cancel_requested()
        );
        let cancel_reason = inner.read().cancel_reason.clone();
        crate::assert_with_log!(
            cancel_reason == Some(CancelReason::timeout()),
            "cancel_reason",
            Some(CancelReason::timeout()),
            cancel_reason
        );
        let requested_state = matches!(t.state, TaskState::CancelRequested { .. });
        crate::assert_with_log!(
            requested_state,
            "state cancel requested",
            true,
            requested_state
        );
        crate::test_complete!("request_cancel_updates_shared_cx");
    }

    #[test]
    fn direct_cx_wake_is_not_republished_by_checkpoint_materialization() {
        init_test("direct_cx_wake_is_not_republished_by_checkpoint_materialization");

        struct CountWake(Arc<AtomicUsize>);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        let cx: crate::cx::Cx<crate::cx::cap::All> = crate::cx::Cx::from_inner(Arc::clone(&inner));
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));
        record.start_running();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        inner.write().cancel_waker = Some(Arc::new(CancelWaker::new(waker)));

        cx.cancel_fast(crate::types::CancelKind::RaceLost);
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(!inner.read().cancel_wakers_pending);

        assert!(cx.checkpoint().is_err());
        let (receipt, wakes) = record.consume_checkpoint_cancel_ack().into_parts();
        assert!(
            receipt.is_some(),
            "checkpoint must materialize TaskRecord cancellation"
        );
        assert!(
            wakes.is_empty(),
            "direct Cx producer already paid the wake debt"
        );
        wakes.dispatch();

        assert!(matches!(record.state, TaskState::Cancelling { .. }));
        assert_eq!(
            wake_count.load(Ordering::SeqCst),
            1,
            "checkpoint reconciliation must not dispatch the same Waker twice"
        );
        crate::test_complete!("direct_cx_wake_is_not_republished_by_checkpoint_materialization");
    }

    #[test]
    fn delegated_publication_promotes_stronger_cx_reason_before_wakers() {
        init_test("delegated_publication_promotes_stronger_cx_reason_before_wakers");

        struct CountWake(Arc<AtomicUsize>);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        {
            let mut guard = inner.write();
            guard.runnable_publication = RunnablePublication::Unpublished;
            guard.runnable_publication.delegate_cancel();
        }
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));

        let lower = CancelReason::user("delegated lower priority");
        let lower_priority = lower.cleanup_budget().priority;
        let (update, lower_wakes) = record.request_cancel_for_handle(&lower).into_parts();
        assert_eq!(
            update.route,
            Some(HandleCancelRoute {
                priority: lower_priority,
                delegated_initial: true,
            })
        );
        assert!(lower_wakes.is_empty());
        lower_wakes.dispatch();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        let stronger = CancelReason::shutdown();
        let stronger_priority = stronger.cleanup_budget().priority;
        {
            let mut guard = inner.write();
            guard
                .cancel_reason
                .as_mut()
                .expect("lower reason installed")
                .strengthen(&stronger);
            guard.cancel_wakers_pending = true;
            guard.cancel_waker = Some(Arc::new(CancelWaker::new(waker)));
        }

        let lane_published = AtomicBool::new(false);
        let (published, wakes) = record
            .publish_delegated_cancel_lane(|priority, is_local, pinned_worker| {
                assert_eq!(priority, stronger_priority);
                assert!(!is_local);
                assert_eq!(pinned_worker, None);
                lane_published.store(true, Ordering::SeqCst);
                Some(priority)
            })
            .into_parts();
        assert_eq!(published, Some(stronger_priority));
        assert!(lane_published.load(Ordering::SeqCst));
        assert!(!wakes.is_empty());
        assert!(inner.read().runnable_publication.is_published());
        assert!(!inner.read().cancel_wakers_pending);
        assert!(matches!(
            &record.state,
            TaskState::CancelRequested {
                reason,
                cleanup_budget,
            } if reason.is_kind(crate::types::cancel::CancelKind::Shutdown)
                && cleanup_budget.priority == stronger_priority
        ));
        wakes.dispatch();
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);

        let (repeat, repeat_wakes) = record
            .publish_delegated_cancel_lane(|_, _, _| -> Option<u8> {
                panic!("an already-published command must not insert another lane")
            })
            .into_parts();
        assert_eq!(repeat, None);
        assert!(repeat_wakes.is_empty());
        repeat_wakes.dispatch();
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        crate::test_complete!("delegated_publication_promotes_stronger_cx_reason_before_wakers");
    }

    #[test]
    fn failed_delegated_publication_retires_snapshot_after_outer_lock() {
        struct DropProbe {
            outer_lock: Arc<parking_lot::Mutex<()>>,
            drops: Arc<AtomicUsize>,
            drops_under_outer_lock: Arc<AtomicUsize>,
        }

        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for DropProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                if self.outer_lock.try_lock().is_none() {
                    self.drops_under_outer_lock.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        let outer_lock = Arc::new(parking_lot::Mutex::new(()));
        let drops = Arc::new(AtomicUsize::new(0));
        let drops_under_outer_lock = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(RwLock::new(CxInner::new(
            region(),
            task(),
            Budget::INFINITE,
        )));
        {
            let mut guard = inner.write();
            guard.runnable_publication = RunnablePublication::Unpublished;
            guard.runnable_publication.delegate_cancel();
            guard.cancel_waker = Some(Arc::new(CancelWaker::new(std::task::Waker::from(
                Arc::new(DropProbe {
                    outer_lock: Arc::clone(&outer_lock),
                    drops: Arc::clone(&drops),
                    drops_under_outer_lock: Arc::clone(&drops_under_outer_lock),
                }),
            ))));
        }
        let mut record = TaskRecord::new(task(), region(), Budget::INFINITE);
        record.set_cx_inner(Arc::clone(&inner));
        let (_, request_wakes) = record
            .request_cancel_for_handle(&CancelReason::shutdown())
            .into_parts();
        request_wakes.dispatch();

        let outer_guard = outer_lock.lock();
        let (publication, retirement) = record
            .publish_delegated_cancel_lane(|_, _, _| None::<u8>)
            .into_parts();
        assert_eq!(publication, None);
        assert_eq!(retirement.len(), 1);
        let registry_owner = inner.write().cancel_waker.take();
        drop(registry_owner);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the failed attempt must not retire its snapshot under the outer lock"
        );

        drop(outer_guard);
        retirement.retire_without_dispatch();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            drops_under_outer_lock.load(Ordering::SeqCst),
            0,
            "the final RawWaker destructor runs only after the outer lock is gone"
        );
    }

    #[test]
    fn task_record_cancel_witness_snapshot_scrubs_ids() {
        init_test("task_record_cancel_witness_snapshot_scrubs_ids");
        let mut record = TaskRecord::new(
            TaskId::new_for_test(4, 2),
            RegionId::new_for_test(8, 1),
            Budget::new().with_poll_quota(5),
        );
        let requested = request_cancel(
            &mut record,
            CancelReason::linked_exit()
                .with_region(RegionId::new_for_test(77, 6))
                .with_task(TaskId::new_for_test(11, 5))
                .with_timestamp(Time::from_nanos(44))
                .with_message("peer closed"),
        );
        crate::assert_with_log!(requested, "request_cancel", true, requested);

        insta::assert_json_snapshot!(
            "task_record_cancel_witness_scrubbed_ids",
            scrub_task_record_ids(
                serde_json::to_value(record.cancel_witness().expect("cancel witness"))
                    .expect("serialize witness")
            )
        );
        crate::test_complete!("task_record_cancel_witness_snapshot_scrubs_ids");
    }

    /// Enhanced scrubbing function for TaskRecord snapshots that handles timing fields
    fn scrub_task_record_state(value: Value) -> Value {
        let mut scrubbed = scrub_task_record_ids(value);

        // Scrub timing fields that vary between test runs
        if let Some(created_at) = scrubbed.pointer_mut("/created_at") {
            *created_at = json!(0);
        }

        if let Some(created_instant) = scrubbed.pointer_mut("/created_instant") {
            *created_instant = json!("[INSTANT]");
        }

        if let Some(timestamp) = scrubbed.pointer_mut("/reason/timestamp") {
            *timestamp = json!("[TIMESTAMP]");
        }

        scrubbed
    }

    #[test]
    fn task_record_lifecycle_states_snapshot() {
        init_test("task_record_lifecycle_states_snapshot");

        // Test each major lifecycle phase with golden snapshots
        let task_id = TaskId::new_for_test(1, 0);
        let region_id = RegionId::new_for_test(2, 0);
        let budget = Budget::new().with_poll_quota(100_000);

        // Phase 1: Created state
        let record_created = TaskRecord::new(task_id, region_id, budget);
        insta::assert_json_snapshot!(
            "task_record_state_created",
            scrub_task_record_state(
                serde_json::to_value(&record_created)
                    .expect("should serialize created task record")
            )
        );

        // Phase 2: Running state
        let mut record_running = TaskRecord::new(task_id, region_id, budget);
        let started = record_running.start_running();
        crate::assert_with_log!(started, "start_running", true, started);
        insta::assert_json_snapshot!(
            "task_record_state_running",
            scrub_task_record_state(
                serde_json::to_value(&record_running)
                    .expect("should serialize running task record")
            )
        );

        // Phase 3: CancelRequested state with timeout reason
        let mut record_cancel_requested = TaskRecord::new(task_id, region_id, budget);
        let requested = request_cancel(
            &mut record_cancel_requested,
            CancelReason::timeout()
                .with_timestamp(Time::from_nanos(123456789))
                .with_message("operation timeout"),
        );
        crate::assert_with_log!(requested, "request_cancel", true, requested);
        insta::assert_json_snapshot!(
            "task_record_state_cancel_requested",
            scrub_task_record_state(
                serde_json::to_value(&record_cancel_requested)
                    .expect("should serialize cancel_requested task record")
            )
        );

        // Phase 4: Cancelling state
        let mut record_cancelling = TaskRecord::new(task_id, region_id, budget);
        let _ = request_cancel(&mut record_cancelling, CancelReason::user("abort"));
        let ack = record_cancelling.acknowledge_cancel();
        crate::assert_with_log!(ack.is_some(), "acknowledge_cancel", true, ack.is_some());
        insta::assert_json_snapshot!(
            "task_record_state_cancelling",
            scrub_task_record_state(
                serde_json::to_value(&record_cancelling)
                    .expect("should serialize cancelling task record")
            )
        );

        // Phase 5: Finalizing state
        let mut record_finalizing = TaskRecord::new(task_id, region_id, budget);
        let _ = request_cancel(&mut record_finalizing, CancelReason::shutdown());
        let _ = record_finalizing.acknowledge_cancel();
        let cleaned = record_finalizing.cleanup_done();
        crate::assert_with_log!(cleaned, "cleanup_done", true, cleaned);
        insta::assert_json_snapshot!(
            "task_record_state_finalizing",
            scrub_task_record_state(
                serde_json::to_value(&record_finalizing).expect("serialize finalizing")
            )
        );

        // Phase 6: Completed(Ok) state
        let mut record_completed_ok = TaskRecord::new(task_id, region_id, budget);
        let completed = record_completed_ok.complete(Outcome::Ok(()));
        crate::assert_with_log!(completed, "complete ok", true, completed);
        insta::assert_json_snapshot!(
            "task_record_state_completed_ok",
            scrub_task_record_state(
                serde_json::to_value(&record_completed_ok).expect("serialize completed_ok")
            )
        );

        // Phase 7: Completed(Err) state
        let mut record_completed_err = TaskRecord::new(task_id, region_id, budget);
        let err = Error::new(ErrorKind::User);
        let completed = record_completed_err.complete(Outcome::Err(err));
        crate::assert_with_log!(completed, "complete err", true, completed);
        insta::assert_json_snapshot!(
            "task_record_state_completed_err",
            scrub_task_record_state(
                serde_json::to_value(&record_completed_err).expect("serialize completed_err")
            )
        );

        // Phase 8: Completed(Cancelled) state through full protocol
        let mut record_completed_cancelled = TaskRecord::new(task_id, region_id, budget);
        let _ = request_cancel(
            &mut record_completed_cancelled,
            CancelReason::linked_exit()
                .with_region(RegionId::new_for_test(5, 1))
                .with_task(TaskId::new_for_test(7, 2)),
        );
        let _ = record_completed_cancelled.acknowledge_cancel();
        let _ = record_completed_cancelled.cleanup_done();
        let finalized = record_completed_cancelled.finalize_done();
        crate::assert_with_log!(finalized, "finalize_done", true, finalized);
        insta::assert_json_snapshot!(
            "task_record_state_completed_cancelled",
            scrub_task_record_state(
                serde_json::to_value(&record_completed_cancelled)
                    .expect("serialize completed_cancelled")
            )
        );

        crate::test_complete!("task_record_lifecycle_states_snapshot");
    }

    #[test]
    fn task_record_cancel_reasons_snapshot() {
        init_test("task_record_cancel_reasons_snapshot");

        let task_id = TaskId::new_for_test(3, 1);
        let region_id = RegionId::new_for_test(4, 1);
        let budget = Budget::new().with_poll_quota(5);

        // Test different cancel reason types
        let cancel_reasons = vec![
            CancelReason::timeout()
                .with_timestamp(Time::from_nanos(100))
                .with_message("request timeout"),
            CancelReason::user("manual abort").with_timestamp(Time::from_nanos(200)),
            CancelReason::shutdown().with_message("graceful shutdown"),
            CancelReason::linked_exit()
                .with_region(RegionId::new_for_test(10, 2))
                .with_task(TaskId::new_for_test(20, 3))
                .with_message("dependency failed"),
        ];

        for (i, reason) in cancel_reasons.into_iter().enumerate() {
            let mut record = TaskRecord::new(task_id, region_id, budget);
            let _ = request_cancel(&mut record, reason);

            let snapshot_name = format!("task_record_cancel_reason_{}", i);
            insta::assert_json_snapshot!(
                snapshot_name,
                scrub_task_record_state(
                    serde_json::to_value(&record).expect("serialize cancel reason")
                )
            );
        }

        crate::test_complete!("task_record_cancel_reasons_snapshot");
    }

    #[test]
    fn task_record_budget_variants_snapshot() {
        init_test("task_record_budget_variants_snapshot");

        let task_id = TaskId::new_for_test(6, 1);
        let region_id = RegionId::new_for_test(7, 1);

        // Test different budget configurations
        let budgets = vec![
            Budget::INFINITE,
            Budget::new().with_poll_quota(1),
            Budget::new().with_poll_quota(100),
            Budget::new().with_poll_quota(u32::MAX),
        ];

        for (i, budget) in budgets.into_iter().enumerate() {
            let record = TaskRecord::new(task_id, region_id, budget);

            let snapshot_name = format!("task_record_budget_{}", i);
            insta::assert_json_snapshot!(
                snapshot_name,
                scrub_task_record_state(serde_json::to_value(&record).expect("serialize budget"))
            );
        }

        crate::test_complete!("task_record_budget_variants_snapshot");
    }

    #[test]
    fn task_record_transition_sequence_snapshot() {
        init_test("task_record_transition_sequence_snapshot");

        // Test complete transition sequence with snapshots at each step
        let task_id = TaskId::new_for_test(9, 1);
        let region_id = RegionId::new_for_test(11, 1);
        let budget = Budget::new().with_poll_quota(100_000);

        let mut record = TaskRecord::new(task_id, region_id, budget);

        // Capture sequence: Created → Running → CancelRequested → Cancelling → Finalizing → Completed
        let mut sequence = Vec::new();

        // Step 1: Created
        sequence.push(("created", serde_json::to_value(&record).expect("serialize")));

        // Step 2: Running
        let _ = record.start_running();
        sequence.push(("running", serde_json::to_value(&record).expect("serialize")));

        // Step 3: CancelRequested
        let _ = request_cancel(
            &mut record,
            CancelReason::shutdown().with_message("shutdown initiated"),
        );
        sequence.push((
            "cancel_requested",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Step 4: Cancelling
        let _ = record.acknowledge_cancel();
        sequence.push((
            "cancelling",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Step 5: Finalizing
        let _ = record.cleanup_done();
        sequence.push((
            "finalizing",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Step 6: Completed
        let _ = record.finalize_done();
        sequence.push((
            "completed",
            serde_json::to_value(&record).expect("serialize"),
        ));

        // Create snapshot for complete sequence
        let scrubbed_sequence: Vec<_> = sequence
            .into_iter()
            .map(|(phase, value)| (phase, scrub_task_record_state(value)))
            .collect();

        insta::assert_json_snapshot!("task_record_transition_sequence", scrubbed_sequence);

        crate::test_complete!("task_record_transition_sequence_snapshot");
    }

    // =================================================================
    // TaskPhase transition table validation (bd-2qqyi)
    // =================================================================

    use TaskPhase::*;

    #[test]
    fn valid_transitions_accepted() {
        init_test("valid_transitions_accepted");
        let valid = [
            (Created, Running),
            (Created, CancelRequested),
            (Created, Completed), // err/panic at spawn
            (Running, CancelRequested),
            (Running, Completed),
            (CancelRequested, CancelRequested), // strengthen
            (CancelRequested, Cancelling),
            (CancelRequested, Completed), // err/panic before ack
            (Cancelling, Cancelling),     // strengthen
            (Cancelling, Finalizing),
            (Cancelling, Completed),  // err/panic during cleanup
            (Finalizing, Finalizing), // strengthen
            (Finalizing, Completed),
        ];

        for (from, to) in valid {
            crate::assert_with_log!(
                from.is_valid_transition(to),
                "transition should be valid",
                true,
                (from, to)
            );
        }
        crate::test_complete!("valid_transitions_accepted");
    }

    #[test]
    fn invalid_transitions_rejected() {
        init_test("invalid_transitions_rejected");
        let invalid = [
            // Backwards transitions
            (Running, Created),
            (CancelRequested, Running),
            (CancelRequested, Created),
            (Cancelling, CancelRequested),
            (Cancelling, Running),
            (Cancelling, Created),
            (Finalizing, Cancelling),
            (Finalizing, CancelRequested),
            (Finalizing, Running),
            (Finalizing, Created),
            // Skipped states
            (Created, Cancelling),
            (Created, Finalizing),
            (Running, Cancelling),
            (Running, Finalizing),
            (CancelRequested, Finalizing),
            // Terminal: no transitions out
            (Completed, Created),
            (Completed, Running),
            (Completed, CancelRequested),
            (Completed, Cancelling),
            (Completed, Finalizing),
            (Completed, Completed),
        ];

        for (from, to) in invalid {
            crate::assert_with_log!(
                !from.is_valid_transition(to),
                "transition should be invalid",
                false,
                (from, to)
            );
        }
        crate::test_complete!("invalid_transitions_rejected");
    }

    #[test]
    fn transition_table_is_exhaustive() {
        init_test("transition_table_is_exhaustive");
        let phases = [
            Created,
            Running,
            CancelRequested,
            Cancelling,
            Finalizing,
            Completed,
        ];

        // Every (from, to) pair should be either valid or invalid — never panic
        let mut valid_count = 0;
        let mut invalid_count = 0;
        for from in phases {
            for to in phases {
                if from.is_valid_transition(to) {
                    valid_count += 1;
                } else {
                    invalid_count += 1;
                }
            }
        }
        // 6x6 = 36 total pairs; 13 valid (see valid_transitions_accepted)
        crate::assert_with_log!(
            valid_count == 13,
            "valid transitions count",
            13,
            valid_count
        );
        crate::assert_with_log!(
            invalid_count == 23,
            "invalid transitions count",
            23,
            invalid_count
        );
        crate::test_complete!("transition_table_is_exhaustive");
    }

    // Proptest support for TaskPhase
    #[cfg(feature = "test-internals")]
    mod proptest_support {
        use super::TaskPhase;
        use proptest::prelude::*;

        impl Arbitrary for TaskPhase {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                prop_oneof![
                    Just(TaskPhase::Created),
                    Just(TaskPhase::Running),
                    Just(TaskPhase::CancelRequested),
                    Just(TaskPhase::Cancelling),
                    Just(TaskPhase::Finalizing),
                    Just(TaskPhase::Completed),
                ]
                .boxed()
            }
        }
    }
