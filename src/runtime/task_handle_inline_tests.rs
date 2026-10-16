    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::cap;
    use crate::test_utils::init_test_logging;
    use crate::types::CancelKind;
    use crate::util::ArenaIndex;
    use serde_json::{Value, json};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn task_handle_snapshot<T>(handle: &TaskHandle<T>) -> Value {
        json!({
            "task_id": handle.task_id(),
            "is_finished": handle.is_finished(),
            "terminal_consumed": handle.terminal_consumed_for_test(),
        })
    }

    fn scrub_task_handle_ids(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(task_id) = scrubbed.pointer_mut("/pending/task_id") {
            *task_id = json!("[TASK_ID]");
        }

        if let Some(task_id) = scrubbed.pointer_mut("/consumed/task_id") {
            *task_id = json!("[TASK_ID]");
        }

        scrubbed
    }

    #[test]
    fn spawn_completion_policy_distinguishes_acknowledgement_and_dominance() {
        let reason = CancelReason::user("abort");

        assert_eq!(
            classify_spawn_completion(
                SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
                false,
                true,
                true,
                Some(reason.clone()),
                7_u8,
            ),
            Ok(7),
            "ordinary completion keeps the result of acknowledged cancellation",
        );
        assert!(matches!(
            classify_spawn_completion(
                SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
                false,
                false,
                true,
                Some(reason.clone()),
                7_u8,
            ),
            Err(JoinError::Cancelled(_))
        ));
        assert!(matches!(
            classify_spawn_completion(
                SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
                true,
                true,
                true,
                Some(reason.clone()),
                7_u8,
            ),
            Err(JoinError::Cancelled(_))
        ));
        assert!(matches!(
            classify_spawn_completion(
                SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
                false,
                true,
                true,
                None,
                7_u8,
            ),
            Err(JoinError::Cancelled(_))
        ));
        assert!(matches!(
            classify_spawn_completion(
                SpawnCompletionPolicy::CancellationDominant,
                false,
                true,
                true,
                Some(reason),
                7_u8,
            ),
            Err(JoinError::Cancelled(_))
        ));
        match classify_spawn_completion(
            SpawnCompletionPolicy::CancellationDominant,
            true,
            true,
            true,
            None,
            7_u8,
        ) {
            Err(JoinError::Cancelled(reason)) => {
                assert_eq!(reason.message.as_deref(), Some("join channel closed"));
            }
            other => panic!("reasonless cancellation must retain its v0.4.3 fallback: {other:?}"),
        }
    }

    #[test]
    fn spawn_completion_preserves_reasonless_cancellation_compatibility() {
        let cx = Cx::for_testing();
        cx.inner.write().fast_cancel =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let observed = block_on(observe_spawn_completion(
            async { 7_u8 },
            cx,
            SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
        ));

        match observed.classify() {
            Err(JoinError::Cancelled(reason)) => {
                assert_eq!(reason.message.as_deref(), Some("join channel closed"));
            }
            other => panic!(
                "v0.4.3 classified reasonless cancellation as an outer join cancellation: {other:?}"
            ),
        }
    }

    #[test]
    fn completion_state_is_frozen_after_terminal_observation() {
        for policy in [
            SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            SpawnCompletionPolicy::CancellationDominant,
        ] {
            let cx = Cx::for_testing();
            let observed = block_on(observe_spawn_completion(async { 7_u8 }, cx.clone(), policy));

            cx.cancel_with(
                crate::types::CancelKind::User,
                Some("late abort after Poll::Ready"),
            );

            assert_eq!(
                observed.classify(),
                Ok(7),
                "cancellation requested after terminal observation must not overwrite an already-classified value under {policy:?}",
            );
        }
    }

    #[test]
    fn task_handle_basic() {
        init_test("task_handle_basic");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        crate::assert_with_log!(
            handle.task_id() == task_id,
            "task id matches",
            task_id,
            handle.task_id()
        );
        crate::assert_with_log!(
            !handle.is_finished(),
            "handle not finished",
            false,
            handle.is_finished()
        );

        // Send the result
        crate::test_section!("send");
        tx.send(&cx, Ok::<i32, JoinError>(42)).expect("send failed");

        // Join should succeed
        crate::test_section!("join");
        let result = block_on(handle.join(&cx));
        let expected: Result<i32, JoinError> = Ok(42);
        crate::assert_with_log!(result == expected, "join result", expected, result);
        crate::test_complete!("task_handle_basic");
    }

    #[test]
    fn task_handle_cancelled() {
        init_test("task_handle_cancelled");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        // Send a cancelled result
        crate::test_section!("send");
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Cancelled(CancelReason::race_loser())),
        )
        .expect("send failed");

        crate::test_section!("join");
        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Cancelled(r)) => {
                crate::assert_with_log!(
                    matches!(r.kind, crate::types::CancelKind::RaceLost),
                    "cancel kind is race lost",
                    crate::types::CancelKind::RaceLost,
                    r.kind
                );
            }
            _ => unreachable!("expected Cancelled"),
        }
        crate::test_complete!("task_handle_cancelled");
    }

    #[test]
    fn join_closed_uses_cancel_reason() {
        init_test("join_closed_uses_cancel_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        {
            let mut lock = cx.inner.write();
            lock.set_cancel_requested(true);
            lock.cancel_reason = Some(CancelReason::timeout());
        }

        drop(tx);
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Cancelled(r)) => {
                crate::assert_with_log!(
                    r.kind == CancelKind::Timeout,
                    "cancel kind is timeout",
                    CancelKind::Timeout,
                    r.kind
                );
            }
            _ => unreachable!("expected Cancelled"),
        }
        crate::test_complete!("join_closed_uses_cancel_reason");
    }

    #[test]
    fn task_handle_panicked() {
        init_test("task_handle_panicked");
        crate::test_section!("setup");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        crate::test_section!("send");
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Panicked(PanicPayload::new("boom"))),
        )
        .expect("send failed");

        crate::test_section!("join");
        let result = block_on(handle.join(&cx));
        match result {
            Err(JoinError::Panicked(p)) => {
                let payload = p.to_string();
                crate::assert_with_log!(
                    payload.contains("boom"),
                    "panic payload contains boom",
                    true,
                    payload
                );
            }
            _ => unreachable!("expected Panicked"),
        }
        crate::test_complete!("task_handle_panicked");
    }

    #[test]
    fn join_error_display() {
        init_test("join_error_display");
        let cancelled = JoinError::Cancelled(CancelReason::user("stop"));
        let cancelled_text = cancelled.to_string();
        crate::assert_with_log!(
            cancelled_text.contains("task was cancelled"),
            "cancelled display mentions cancelled",
            true,
            cancelled_text
        );
        crate::assert_with_log!(
            cancelled_text.contains("stop"),
            "cancelled display includes reason",
            true,
            cancelled_text
        );

        let panicked = JoinError::Panicked(PanicPayload::new("crash"));
        let panicked_text = panicked.to_string();
        crate::assert_with_log!(
            panicked_text.contains("task panicked"),
            "panicked display mentions panic",
            true,
            panicked_text
        );
        crate::assert_with_log!(
            panicked_text.contains("crash"),
            "panicked display includes payload",
            true,
            panicked_text
        );

        let terminal = JoinError::PolledAfterCompletion;
        let terminal_text = terminal.to_string();
        crate::assert_with_log!(
            terminal_text.contains("polled after completion"),
            "terminal repoll display mentions completion",
            true,
            terminal_text
        );
        crate::test_complete!("join_error_display");
    }

    #[test]
    fn drop_join_does_not_abort_if_result_already_ready() {
        init_test("drop_join_does_not_abort_if_result_already_ready");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(9, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok::<i32, JoinError>(7))
            .expect("send should succeed");

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        drop(handle.join(&cx));

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "dropping a ready join must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "dropping a ready join must not overwrite cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("drop_join_does_not_abort_if_result_already_ready");
    }

    #[test]
    fn drop_join_does_not_abort_if_channel_already_closed() {
        init_test("drop_join_does_not_abort_if_channel_already_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        drop(tx);

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        drop(handle.join(&cx));

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "dropping a closed join must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "dropping a closed join must not overwrite cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("drop_join_does_not_abort_if_channel_already_closed");
    }

    #[test]
    fn drop_task_handle_detaches_without_requesting_cancel() {
        init_test("drop_task_handle_detaches_without_requesting_cancel");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 1));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        drop(handle);

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "dropping TaskHandle itself must detach rather than request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "detaching by dropping TaskHandle must not stamp a cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("drop_task_handle_detaches_without_requesting_cancel");
    }

    #[test]
    fn abort_then_join_closed_channel_preserves_abort_reason() {
        init_test("abort_then_join_closed_channel_preserves_abort_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 2));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        handle.abort_with_reason(CancelReason::timeout());
        crate::assert_with_log!(
            cx.is_cancel_requested(),
            "TaskHandle abort publishes through its live Cx envelope",
            true,
            cx.is_cancel_requested()
        );
        drop(tx);

        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Timeout,
                    ..
                }))
            ),
            "join after explicit abort preserves the stronger timeout reason",
            "Err(JoinError::Cancelled(Timeout))",
            format!("{result:?}")
        );
        crate::test_complete!("abort_then_join_closed_channel_preserves_abort_reason");
    }

    #[test]
    fn late_abort_cannot_reopen_completed_cancel_waker_registry() {
        init_test("late_abort_cannot_reopen_completed_cancel_waker_registry");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 20));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&cx.inner));

        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);
        handle.abort_with_reason(CancelReason::shutdown());

        let inner = cx.inner.read();
        assert!(inner.cancel_requested);
        assert!(
            inner
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown))
        );
        assert!(inner.cancel_waker_registry_closed);
        assert!(
            !inner.cancel_wakers_pending,
            "a terminal context cannot acquire new Waker publication debt"
        );
        crate::test_complete!("late_abort_cannot_reopen_completed_cancel_waker_registry");
    }

    #[test]
    fn abort_reason_survives_task_context_teardown() {
        init_test("abort_reason_survives_task_context_teardown");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 3));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        handle.abort_with_reason(CancelReason::race_loser());
        drop(tx);

        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                }))
            ),
            "closed join retains explicit reason after task context teardown",
            "Err(JoinError::Cancelled(RaceLost))",
            format!("{result:?}")
        );
        crate::test_complete!("abort_reason_survives_task_context_teardown");
    }

    #[test]
    fn pending_try_join_uses_admitted_context_cancel_reason() {
        init_test("pending_try_join_uses_admitted_context_cancel_reason");
        let cx = test_cx();
        let provisional = TaskId::from_arena(ArenaIndex::new(10, 4));
        let canonical = TaskId::from_arena(ArenaIndex::new(10, 5));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, Arc::clone(&admitted));

        admitted
            .set(crate::runtime::spawn_mailbox::AdmittedTask::published(
                canonical,
                Arc::downgrade(&cx.inner),
            ))
            .expect("admitted identity publishes");
        cx.set_cancel_reason(CancelReason::shutdown());
        drop(tx);

        let result = handle.try_join();
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Shutdown,
                    ..
                }))
            ),
            "try_join resolves the admitted mailbox context dynamically",
            "Err(JoinError::Cancelled(Shutdown))",
            format!("{result:?}")
        );
        crate::test_complete!("pending_try_join_uses_admitted_context_cancel_reason");
    }

    #[test]
    fn pending_join_resolves_admission_after_future_construction() {
        init_test("pending_join_resolves_admission_after_future_construction");
        let cx = test_cx();
        let provisional = TaskId::from_arena(ArenaIndex::new(10, 6));
        let canonical = TaskId::from_arena(ArenaIndex::new(10, 7));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, Arc::clone(&admitted));

        let join = handle.join(&cx);
        admitted
            .set(crate::runtime::spawn_mailbox::AdmittedTask::published(
                canonical,
                Arc::downgrade(&cx.inner),
            ))
            .expect("late admitted identity publishes");
        cx.set_cancel_reason(CancelReason::timeout());
        drop(tx);

        let result = block_on(join);
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Timeout,
                    ..
                }))
            ),
            "join future resolves admission published after construction",
            "Err(JoinError::Cancelled(Timeout))",
            format!("{result:?}")
        );
        crate::test_complete!("pending_join_resolves_admission_after_future_construction");
    }

    #[test]
    fn pending_requested_reason_strengthens_queued_denial() {
        init_test("pending_requested_reason_strengthens_queued_denial");
        let cx = test_cx();
        let provisional = TaskId::from_arena(ArenaIndex::new(10, 8));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, admitted);

        tx.send(
            &cx,
            Err(JoinError::Cancelled(CancelReason::user(
                "spawn admission failed",
            ))),
        )
        .expect("denial result queues");
        handle.abort_with_reason(CancelReason::race_loser());

        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                }))
            ),
            "queued weaker denial is strengthened by pending RaceLost request",
            "Err(JoinError::Cancelled(RaceLost))",
            format!("{result:?}")
        );

        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let admitted = Arc::new(crate::runtime::spawn_mailbox::AdmittedTaskSlot::new());
        let mut handle = TaskHandle::new_pending(provisional, rx, admitted);
        tx.send(
            &cx,
            Err(JoinError::Cancelled(CancelReason::user(
                "spawn admission failed",
            ))),
        )
        .expect("second denial result queues");
        handle.abort_with_reason(CancelReason::race_loser());
        let try_result = handle.try_join();
        crate::assert_with_log!(
            matches!(
                try_result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                }))
            ),
            "try_join also strengthens a queued weaker denial",
            "Err(JoinError::Cancelled(RaceLost))",
            format!("{try_result:?}")
        );
        crate::test_complete!("pending_requested_reason_strengthens_queued_denial");
    }

    #[test]
    fn concurrent_pending_abort_requests_keep_strongest_reason() {
        init_test("concurrent_pending_abort_requests_keep_strongest_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(10, 9));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let handle = Arc::new(TaskHandle::new(task_id, rx, Weak::new()));
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let race_handle = Arc::clone(&handle);
        let race_barrier = Arc::clone(&barrier);
        let race = std::thread::spawn(move || {
            race_barrier.wait();
            for _ in 0..128 {
                race_handle.abort_with_reason(CancelReason::race_loser());
            }
        });
        let shutdown_handle = Arc::clone(&handle);
        let shutdown_barrier = Arc::clone(&barrier);
        let shutdown = std::thread::spawn(move || {
            shutdown_barrier.wait();
            for _ in 0..128 {
                shutdown_handle.abort_with_reason(CancelReason::shutdown());
            }
        });
        barrier.wait();
        race.join().expect("RaceLost abort thread completes");
        shutdown.join().expect("Shutdown abort thread completes");

        let mut handle = Arc::try_unwrap(handle).expect("abort threads release handle");
        drop(tx);
        let result = block_on(handle.join(&cx));
        crate::assert_with_log!(
            matches!(
                result,
                Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Shutdown,
                    ..
                }))
            ),
            "concurrent abort requests retain the strongest reason",
            "Err(JoinError::Cancelled(Shutdown))",
            format!("{result:?}")
        );
        crate::test_complete!("concurrent_pending_abort_requests_keep_strongest_reason");
    }

    #[test]
    fn join_future_repoll_after_success_fails_closed() {
        init_test("join_future_repoll_after_success_fails_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(11, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok::<i32, JoinError>(7))
            .expect("send should succeed");

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let mut join = Box::pin(handle.join(&cx));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let first = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(7))),
            "first poll yields successful join result",
            "Poll::Ready(Ok(7))",
            format!("{first:?}")
        );

        let second = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "terminal join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{second:?}")
        );
        crate::test_complete!("join_future_repoll_after_success_fails_closed");
    }

    #[test]
    fn join_future_repoll_after_cancelled_result_fails_closed() {
        init_test("join_future_repoll_after_cancelled_result_fails_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(12, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(
            &cx,
            Err::<i32, JoinError>(JoinError::Cancelled(CancelReason::race_loser())),
        )
        .expect("send should succeed");

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let mut join = Box::pin(handle.join(&cx));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let first = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(
                first,
                Poll::Ready(Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::RaceLost,
                    ..
                })))
            ),
            "first poll preserves task cancellation result",
            "Poll::Ready(Err(JoinError::Cancelled(RaceLost)))",
            format!("{first:?}")
        );

        let second = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "cancelled join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{second:?}")
        );
        crate::test_complete!("join_future_repoll_after_cancelled_result_fails_closed");
    }

    #[test]
    fn join_future_repoll_after_closed_channel_fails_closed() {
        init_test("join_future_repoll_after_closed_channel_fails_closed");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(13, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        drop(tx);

        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));
        let mut join = Box::pin(handle.join(&cx));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);

        let first = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(JoinError::Cancelled(_)))),
            "closed join still maps to cancelled on first poll",
            "Poll::Ready(Err(JoinError::Cancelled(_)))",
            format!("{first:?}")
        );

        let second = join.as_mut().poll(&mut poll_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "closed join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{second:?}")
        );
        crate::test_complete!("join_future_repoll_after_closed_channel_fails_closed");
    }

    #[test]
    fn defuse_drop_abort_skips_pending_join_abort() {
        init_test("defuse_drop_abort_skips_pending_join_abort");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 0));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        let mut join = handle.join(&cx);
        join.defuse_drop_abort();
        drop(join);

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "defused pending join drop must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "defused pending join drop must not stamp cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("defuse_drop_abort_skips_pending_join_abort");
    }

    #[test]
    fn drop_join_with_weaker_reason_preserves_stronger_existing_cancel_reason() {
        init_test("drop_join_with_weaker_reason_preserves_stronger_existing_cancel_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 1));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        handle.abort_with_reason(CancelReason::timeout());
        drop(handle.join_with_drop_reason(&cx, CancelReason::user("race cleanup")));

        let guard = cx.inner.read();
        let reason = guard
            .cancel_reason
            .clone()
            .expect("drop join should leave existing cancel reason intact");
        crate::assert_with_log!(
            guard.cancel_requested,
            "drop join still marks cancellation requested",
            true,
            guard.cancel_requested
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "weaker drop reason must not downgrade existing timeout cancel reason",
            CancelKind::Timeout,
            reason.kind
        );

        crate::test_complete!(
            "drop_join_with_weaker_reason_preserves_stronger_existing_cancel_reason"
        );
    }

    #[test]
    fn drop_join_with_stronger_reason_strengthens_existing_cancel_reason() {
        init_test("drop_join_with_stronger_reason_strengthens_existing_cancel_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(14, 2));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        handle.abort_with_reason(CancelReason::user("soft stop"));
        drop(handle.join_with_drop_reason(&cx, CancelReason::timeout()));

        let guard = cx.inner.read();
        let reason = guard
            .cancel_reason
            .clone()
            .expect("drop join should strengthen existing cancel reason");
        crate::assert_with_log!(
            guard.cancel_requested,
            "drop join marks cancellation requested",
            true,
            guard.cancel_requested
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "stronger drop reason must upgrade existing cancel reason",
            CancelKind::Timeout,
            reason.kind
        );

        crate::test_complete!("drop_join_with_stronger_reason_strengthens_existing_cancel_reason");
    }

    // =========================================================================
    // Wave 27: Data-type trait coverage
    // =========================================================================

    #[test]
    fn join_error_debug_cancelled() {
        let err = JoinError::Cancelled(CancelReason::user("test"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn join_error_debug_panicked() {
        let err = JoinError::Panicked(PanicPayload::new("oops"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Panicked"));
    }

    #[test]
    fn join_error_debug_polled_after_completion() {
        let err = JoinError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    #[test]
    fn join_error_clone() {
        let err = JoinError::Cancelled(CancelReason::timeout());
        let err2 = err.clone();
        assert_eq!(err, err2);
    }

    #[test]
    fn join_error_eq() {
        let a = JoinError::Cancelled(CancelReason::user("a"));
        let b = JoinError::Cancelled(CancelReason::user("a"));
        assert_eq!(a, b);

        let c = JoinError::Panicked(PanicPayload::new("x"));
        assert_ne!(a, c);
    }

    #[test]
    fn join_error_is_std_error() {
        let err: &dyn std::error::Error = &JoinError::Cancelled(CancelReason::user("e"));
        // std::error::Error requires Display + Debug
        let _ = format!("{err}");
        let _ = format!("{err:?}");
    }

    #[test]
    fn task_handle_debug() {
        let task_id = TaskId::from_arena(ArenaIndex::new(5, 0));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("TaskHandle"));
    }

    #[test]
    fn try_join_not_ready() {
        let task_id = TaskId::from_arena(ArenaIndex::new(20, 0));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let result = handle.try_join();
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn try_join_ready() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(21, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok(99)).expect("send");
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let first = handle.try_join();
        assert_eq!(first.unwrap(), Some(99));
        assert!(handle.terminal_consumed_for_test());

        let second = handle.try_join();
        assert!(matches!(second, Err(JoinError::PolledAfterCompletion)));
    }

    #[test]
    fn try_join_closed_channel() {
        let task_id = TaskId::from_arena(ArenaIndex::new(22, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        drop(tx);
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());
        let first = handle.try_join();
        assert!(matches!(first, Err(JoinError::Cancelled(_))));
        assert!(handle.terminal_consumed_for_test());

        let second = handle.try_join();
        assert!(matches!(second, Err(JoinError::PolledAfterCompletion)));
    }

    #[test]
    fn try_join_after_join_completion_fails_closed() {
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(23, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        tx.send(&cx, Ok(123)).expect("send");
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        let result = block_on(handle.join(&cx));
        assert_eq!(result.unwrap(), 123);
        assert!(handle.terminal_consumed_for_test());

        let second = handle.try_join();
        assert!(matches!(second, Err(JoinError::PolledAfterCompletion)));
    }

    // =========================================================================
    // poll_join: wake registration must survive a Pending poll
    // (br-asupersync-tncxj9)
    // =========================================================================

    fn counting_waker(counter: Arc<std::sync::atomic::AtomicUsize>) -> Waker {
        struct CountingWaker {
            counter: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl std::task::Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        Waker::from(Arc::new(CountingWaker { counter }))
    }

    #[test]
    fn poll_join_pending_registration_survives_repolls_and_completion_wakes() {
        init_test("poll_join_pending_registration_survives_repolls_and_completion_wakes");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(15, 0));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wakes));
        let mut poll_cx = Context::from_waker(&waker);

        // Poll twice. The second Pending must not have discarded the
        // registration installed by the first: a per-poll join future would
        // retire its waiter on drop and leave the caller with no wake source.
        for poll in 0..2 {
            let pending = handle.poll_join(&mut poll_cx);
            crate::assert_with_log!(
                pending.is_pending(),
                "unfinished task polls pending",
                "Poll::Pending",
                format!("poll {poll}: {pending:?}")
            );
        }
        crate::assert_with_log!(
            wakes.load(std::sync::atomic::Ordering::Relaxed) == 0,
            "a still-running task owes no wake",
            0,
            wakes.load(std::sync::atomic::Ordering::Relaxed)
        );

        tx.send(&cx, Ok::<i32, JoinError>(11))
            .expect("result sends");
        crate::assert_with_log!(
            wakes.load(std::sync::atomic::Ordering::Relaxed) == 1,
            "completion wakes the waker registered by the last poll_join",
            1,
            wakes.load(std::sync::atomic::Ordering::Relaxed)
        );

        let ready = handle.poll_join(&mut poll_cx);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(11))),
            "poll_join yields the task result",
            "Poll::Ready(Ok(11))",
            format!("{ready:?}")
        );

        let repoll = handle.poll_join(&mut poll_cx);
        crate::assert_with_log!(
            matches!(repoll, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "terminal poll_join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{repoll:?}")
        );
        crate::test_complete!(
            "poll_join_pending_registration_survives_repolls_and_completion_wakes"
        );
    }

    #[test]
    fn poll_join_pending_does_not_request_cancellation() {
        init_test("poll_join_pending_does_not_request_cancellation");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(15, 1));
        let (_tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        assert!(handle.poll_join(&mut poll_cx).is_pending());
        // Walking away from a poll-based join is not a cancellation request:
        // unlike JoinFuture there is no drop that could carry that meaning.
        drop(handle);

        let (cancel_requested, cancel_reason_is_none) = {
            let guard = cx.inner.read();
            (guard.cancel_requested, guard.cancel_reason.is_none())
        };
        crate::assert_with_log!(
            !cancel_requested,
            "abandoning poll_join must not request cancellation",
            false,
            cancel_requested
        );
        crate::assert_with_log!(
            cancel_reason_is_none,
            "abandoning poll_join must not stamp a cancel reason",
            true,
            cancel_reason_is_none
        );
        crate::test_complete!("poll_join_pending_does_not_request_cancellation");
    }

    fn handle_with_barrier(
        task_id: TaskId,
        rx: oneshot::Receiver<Result<i32, JoinError>>,
        inner: Weak<RwLock<CxInner>>,
        barrier: std::sync::Arc<RetirementBarrier>,
    ) -> TaskHandle<i32> {
        TaskHandle {
            task_id,
            receiver: rx,
            inner,
            admitted: None,
            requested_cancel_reason: std::sync::Arc::new(RwLock::new(None)),
            terminal_consumed: false,
            barrier,
        }
    }

    // br-asupersync-yhueis: a terminal result published before the scheduler
    // retires the record must stay gated behind the retirement barrier, so a
    // consumer cannot surface completion (and a joined owner cannot close its
    // region) before the record commits. Deterministic: no runtime, no sleep.
    #[test]
    fn retirement_barrier_gates_terminal_until_opened_then_delivers_value() {
        init_test("retirement_barrier_gates_terminal_until_opened_then_delivers_value");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(41, 1));
        let (tx, rx) = task_result_channel::<i32>();
        let barrier = RetirementBarrier::pending();
        let mut handle = handle_with_barrier(
            task_id,
            rx,
            std::sync::Arc::downgrade(&cx.inner),
            std::sync::Arc::clone(&barrier),
        );

        // Producer publishes the terminal result up front (pre-retirement).
        publish_terminal_result(tx, Ok(42));

        let wakes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = counting_waker(std::sync::Arc::clone(&wakes));
        let mut poll_cx = Context::from_waker(&waker);

        assert!(
            handle.poll_join(&mut poll_cx).is_pending(),
            "a received terminal must stay gated while the barrier is closed"
        );
        assert!(
            !handle.is_finished(),
            "gated result must not report finished"
        );
        assert!(
            matches!(handle.try_join(), Ok(None)),
            "try_join must report not-ready while gated, registration-free"
        );

        // Opening the barrier (as the scheduler does after the record commits)
        // wakes the parked consumer and releases the gated value unchanged.
        let before = wakes.load(std::sync::atomic::Ordering::SeqCst);
        barrier.open_and_wake();
        assert!(
            wakes.load(std::sync::atomic::Ordering::SeqCst) > before,
            "opening the barrier must wake the parked poll_join waker"
        );
        assert!(
            handle.is_finished(),
            "opened barrier with a result reports finished"
        );
        match handle.poll_join(&mut poll_cx) {
            Poll::Ready(Ok(value)) => assert_eq!(value, 42),
            other => panic!("expected the gated Ok(42) after open, got {other:?}"),
        }
        crate::test_complete!("retirement_barrier_gates_terminal_until_opened_then_delivers_value");
    }

    // br-asupersync-v8yh9s T1: the handle's poll_join and its join() futures
    // share one barrier slot. A join() future dropped without registering
    // (here never polled, its result already published) cleared the slot, so
    // opening the barrier woke nobody and the poll_join waiter hung.
    #[test]
    fn a_dropped_join_future_keeps_the_handles_poll_join_registration() {
        init_test("a_dropped_join_future_keeps_the_handles_poll_join_registration");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(41, 7));
        let (tx, rx) = task_result_channel::<i32>();
        let barrier = RetirementBarrier::pending();
        let mut handle = handle_with_barrier(
            task_id,
            rx,
            std::sync::Arc::downgrade(&cx.inner),
            std::sync::Arc::clone(&barrier),
        );
        publish_terminal_result(tx, Ok(7));
        let wakes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = counting_waker(std::sync::Arc::clone(&wakes));
        let mut poll_cx = Context::from_waker(&waker);
        assert!(handle.poll_join(&mut poll_cx).is_pending());

        drop(handle.join(&cx));
        barrier.open_and_wake();
        assert_eq!(
            wakes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "opening the barrier must wake the poll_join waiter"
        );
        match handle.poll_join(&mut poll_cx) {
            Poll::Ready(Ok(value)) => assert_eq!(value, 7),
            other => panic!("expected Ok(7) after open, got {other:?}"),
        }
        crate::test_complete!("a_dropped_join_future_keeps_the_handles_poll_join_registration");
    }

    // br-asupersync-v8yh9s T2: dropping a join() future dropped its registered
    // waker first, outside any unwind guard. A waker whose destructor panics
    // unwound out of the drop before the drop-abort, so the task was not
    // cancelled.
    #[test]
    fn a_panicking_waker_destructor_does_not_skip_the_join_drop_abort() {
        init_test("a_panicking_waker_destructor_does_not_skip_the_join_drop_abort");
        struct PanicsWhenDropped;
        // The destructor is the point of this waker, so Waker::noop() cannot
        // stand in for it.
        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for PanicsWhenDropped {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        impl Drop for PanicsWhenDropped {
            fn drop(&mut self) {
                panic!("waker destructor");
            }
        }
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(41, 8));
        let (_tx, rx) = task_result_channel::<i32>();
        let barrier = RetirementBarrier::pending();
        let mut handle = handle_with_barrier(
            task_id,
            rx,
            std::sync::Arc::downgrade(&cx.inner),
            std::sync::Arc::clone(&barrier),
        );
        let mut join = Box::pin(handle.join(&cx));
        {
            let waker = Waker::from(std::sync::Arc::new(PanicsWhenDropped));
            assert!(
                join.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        // The barrier now holds the waker's last reference.
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(join)));
        assert!(dropped.is_ok(), "the waker's panic must not unwind out");
        assert!(
            cx.is_cancel_requested(),
            "dropping an unfinished join() future still aborts its task"
        );
        crate::test_complete!("a_panicking_waker_destructor_does_not_skip_the_join_drop_abort");
    }

    // br-asupersync-v8yh9s T3: a waker registered after the barrier opened
    // stayed in the slot (nothing takes it again), so every handle and join
    // future had to lock the barrier on drop to clear it.
    #[test]
    fn an_open_barrier_never_stores_a_waker() {
        init_test("an_open_barrier_never_stores_a_waker");
        let barrier = RetirementBarrier::pending();
        barrier.open_and_wake();
        let waker = counting_waker(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        assert!(barrier.register_and_is_open(&waker));
        assert!(!barrier.has_waker());
        crate::test_complete!("an_open_barrier_never_stores_a_waker");
    }

    // An open barrier (standalone handle, admission denial, unwired paths) must
    // deliver terminal results immediately, preserving v0.4.3 behavior.
    #[test]
    fn open_retirement_barrier_delivers_terminal_immediately() {
        init_test("open_retirement_barrier_delivers_terminal_immediately");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(42, 1));
        let (tx, rx) = task_result_channel::<i32>();
        let mut handle = handle_with_barrier(
            task_id,
            rx,
            std::sync::Arc::downgrade(&cx.inner),
            RetirementBarrier::open_now(),
        );
        publish_terminal_result(tx, Ok(7));
        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        match handle.poll_join(&mut poll_cx) {
            Poll::Ready(Ok(value)) => assert_eq!(value, 7),
            other => panic!("an open barrier must deliver immediately, got {other:?}"),
        }
        crate::test_complete!("open_retirement_barrier_delivers_terminal_immediately");
    }

    #[test]
    fn poll_join_closed_channel_maps_to_cancelled_with_context_reason() {
        init_test("poll_join_closed_channel_maps_to_cancelled_with_context_reason");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(15, 2));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Arc::downgrade(&cx.inner));

        handle.abort_with_reason(CancelReason::timeout());
        drop(tx);

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let closed = handle.poll_join(&mut poll_cx);
        crate::assert_with_log!(
            matches!(
                closed,
                Poll::Ready(Err(JoinError::Cancelled(CancelReason {
                    kind: CancelKind::Timeout,
                    ..
                })))
            ),
            "closed join channel preserves the requested cancel reason",
            "Poll::Ready(Err(JoinError::Cancelled(Timeout)))",
            format!("{closed:?}")
        );

        let repoll = handle.poll_join(&mut poll_cx);
        crate::assert_with_log!(
            matches!(repoll, Poll::Ready(Err(JoinError::PolledAfterCompletion))),
            "closed poll_join repoll fails closed",
            "Poll::Ready(Err(JoinError::PolledAfterCompletion))",
            format!("{repoll:?}")
        );
        crate::test_complete!("poll_join_closed_channel_maps_to_cancelled_with_context_reason");
    }

    #[test]
    fn task_handle_snapshot_scrubs_ids() {
        init_test("task_handle_snapshot_scrubs_ids");
        let cx = test_cx();
        let task_id = TaskId::from_arena(ArenaIndex::new(24, 4));
        let (tx, rx) = oneshot::channel::<Result<i32, JoinError>>();
        let mut handle = TaskHandle::new(task_id, rx, std::sync::Weak::new());

        let pending = task_handle_snapshot(&handle);
        tx.send(&cx, Ok(7)).expect("send");
        let joined = handle.try_join();
        assert_eq!(joined, Ok(Some(7)));
        let consumed = task_handle_snapshot(&handle);

        insta::assert_json_snapshot!(
            "task_handle_scrubbed_ids",
            scrub_task_handle_ids(json!({
                "pending": pending,
                "consumed": consumed,
            }))
        );
        crate::test_complete!("task_handle_snapshot_scrubs_ids");
    }
