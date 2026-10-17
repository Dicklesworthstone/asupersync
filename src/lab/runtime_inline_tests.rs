    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::chaos::ChaosConfig;
    use crate::record::TaskRecord;
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::runtime::deadline_monitor::{AdaptiveDeadlineConfig, WarningReason};
    #[cfg(unix)]
    use crate::runtime::reactor::Interest;
    use crate::runtime::reactor::{Event, Token};
    use crate::types::{Budget, CancelKind, CancelReason, CxInner, Outcome, TaskId};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::task::Waker;
    use std::time::Duration;

    #[cfg(unix)]
    struct TestFdSource;

    #[test]
    fn lab_teardown_releases_parked_task_join_barrier() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Retired(Arc<AtomicBool>);
        impl Drop for Retired {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let mut lab = LabRuntime::new(LabConfig::new(0x16).max_steps(256));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let parked = Arc::new(AtomicBool::new(false));
        let retired = Arc::new(AtomicBool::new(false));
        let child_parked = Arc::clone(&parked);
        let child_retired = Arc::clone(&retired);
        let published = Arc::new(Mutex::new(None));
        let publish = Arc::clone(&published);
        let (owner, _owner_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = crate::Cx::current().unwrap();
                let child = cx
                    .spawn(move |_| async move {
                        let _retired = Retired(child_retired);
                        std::future::poll_fn(|_| {
                            child_parked.store(true, Ordering::Release);
                            std::task::Poll::<()>::Pending
                        })
                        .await;
                    })
                    .unwrap();
                *publish.lock() = Some(child);
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        lab.run_until_idle();
        assert!(parked.load(Ordering::Acquire));
        let mut handle = published.lock().take().expect("published child handle");
        let woken = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(FlagWaker(Arc::clone(&woken))));
        assert!(
            handle
                .poll_join(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        assert!(!handle.is_finished());
        eprintln!(
            "teardown_join scenario=lab task={:?} parked=true trigger=drop",
            handle.task_id()
        );
        drop(lab);
        assert!(retired.load(Ordering::Acquire));
        assert!(woken.load(Ordering::Acquire));
        assert!(handle.is_finished());
        let result = handle.try_join();
        eprintln!("teardown_join scenario=lab retired=true woken=true result={result:?}");
        assert!(
            matches!(result, Err(crate::runtime::task_handle::JoinError::Cancelled(reason))
            if reason.kind == CancelKind::Shutdown)
        );
    }

    #[test]
    fn lab_teardown_releases_unapplied_region_finalizer_acknowledgment() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Retained(Arc<AtomicBool>);
        impl Drop for Retained {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let mut lab = LabRuntime::new(LabConfig::new(0x0001_0017).max_steps(256));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, mut joined) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                crate::Cx::current()
                    .unwrap()
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .unwrap()
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        let region = joined
            .try_join()
            .unwrap()
            .expect("actual child region admitted");
        let dropped = Arc::new(AtomicBool::new(false));
        let woken = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(FlagWaker(Arc::clone(&woken))));
        let mut context = std::task::Context::from_waker(&waker);
        let mut admission = Box::pin(region.retain_until_finalized(Retained(Arc::clone(&dropped))));
        assert!(admission.as_mut().poll(&mut context).is_pending());
        assert!(!dropped.load(Ordering::Acquire));
        assert!(!woken.load(Ordering::Acquire));
        drop(lab);
        assert!(dropped.load(Ordering::Acquire));
        assert!(woken.load(Ordering::Acquire));
        assert!(matches!(
            admission.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(crate::cx::ChildRegionError::RuntimeUnavailable))
        ));
        eprintln!("REGION_FINALIZER_TEARDOWN backend=lab queued=1 retired=1 acknowledgment=closed");
    }
    #[cfg(unix)]
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[cfg(unix)]
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// Waker that sets an `AtomicBool` when woken (for virtual time tests).
    struct FlagWaker(Arc<std::sync::atomic::AtomicBool>);
    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Waker that increments an `AtomicU64` counter when woken.
    struct CountWaker(Arc<std::sync::atomic::AtomicU64>);
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct HandleCancelWakeAudit {
        task_id: TaskId,
        caller_lock: Arc<Mutex<()>>,
        scheduler: Arc<Mutex<LabScheduler>>,
        wake_calls: Arc<std::sync::atomic::AtomicUsize>,
        calls_under_caller_lock: Arc<std::sync::atomic::AtomicUsize>,
        calls_under_scheduler_lock: Arc<std::sync::atomic::AtomicUsize>,
        cancel_lane_published: Arc<std::sync::atomic::AtomicBool>,
    }

    impl std::task::Wake for HandleCancelWakeAudit {
        fn wake(self: Arc<Self>) {
            use std::sync::atomic::Ordering;

            self.wake_calls.fetch_add(1, Ordering::SeqCst);
            let caller_guard = self.caller_lock.try_lock();
            if caller_guard.is_none() {
                self.calls_under_caller_lock.fetch_add(1, Ordering::SeqCst);
            }
            drop(caller_guard);

            if let Some(scheduler) = self.scheduler.try_lock() {
                let mut scheduler = scheduler;
                let observed = scheduler.pop_for_worker(0, 0, Time::ZERO);
                self.cancel_lane_published.store(
                    matches!(observed, Some((task, DispatchLane::Cancel)) if task == self.task_id),
                    Ordering::SeqCst,
                );
                if observed.is_some() {
                    scheduler.schedule_cancel(self.task_id, u8::MAX);
                }
            } else {
                self.calls_under_scheduler_lock
                    .fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn exercise_managed_handle_cancel_boundary(via_join_drop: bool) {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let mut runtime = LabRuntime::new(LabConfig::new(7));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, mut handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                std::future::poll_fn(|_| {
                    if crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            })
            .expect("create managed task");
        let inner = runtime
            .state
            .task(task_id)
            .and_then(|task| task.cx_inner.clone())
            .expect("managed task has a Cx");

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.step_for_test();
        assert!(runtime.scheduler.lock().is_empty());

        let caller_lock = Arc::new(Mutex::new(()));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let calls_under_caller_lock = Arc::new(AtomicUsize::new(0));
        let calls_under_scheduler_lock = Arc::new(AtomicUsize::new(0));
        let cancel_lane_published = Arc::new(AtomicBool::new(false));
        let audit_waker = Waker::from(Arc::new(HandleCancelWakeAudit {
            task_id,
            caller_lock: Arc::clone(&caller_lock),
            scheduler: Arc::clone(&runtime.scheduler),
            wake_calls: Arc::clone(&wake_calls),
            calls_under_caller_lock: Arc::clone(&calls_under_caller_lock),
            calls_under_scheduler_lock: Arc::clone(&calls_under_scheduler_lock),
            cancel_lane_published: Arc::clone(&cancel_lane_published),
        }));
        let retired_waker = {
            let mut guard = inner.write();
            guard
                .cancel_waker
                .replace(Arc::new(crate::types::task_context::CancelWaker::new(
                    audit_waker,
                )))
        };
        drop(retired_waker);

        let join_cx = crate::cx::Cx::for_testing();
        if via_join_drop {
            let join = handle.join_with_drop_reason(&join_cx, CancelReason::timeout());
            let caller_guard = caller_lock.lock();
            drop(join);
            assert_eq!(
                wake_calls.load(Ordering::SeqCst),
                0,
                "JoinFuture::drop must not invoke a cancellation Waker inline"
            );
            drop(caller_guard);
        } else {
            let caller_guard = caller_lock.lock();
            handle.abort_with_reason(CancelReason::timeout());
            handle.abort_with_reason(CancelReason::timeout());
            assert_eq!(
                wake_calls.load(Ordering::SeqCst),
                0,
                "TaskHandle::abort must not invoke a cancellation Waker inline"
            );
            drop(caller_guard);
        }

        {
            let guard = inner.read();
            assert!(
                guard.cancel_requested,
                "managed handle cancellation is checkpoint-visible immediately"
            );
            assert_eq!(
                guard.cancel_reason.as_ref().map(|reason| reason.kind),
                Some(CancelKind::Timeout)
            );
        }
        assert_eq!(runtime.spawn_mailbox.len(), 1, "identical aborts coalesce");
        assert!(runtime.scheduler.lock().is_empty());

        assert_eq!(runtime.run_until_quiescent(), 1);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls_under_caller_lock.load(Ordering::SeqCst), 0);
        assert_eq!(calls_under_scheduler_lock.load(Ordering::SeqCst), 0);
        assert!(cancel_lane_published.load(Ordering::SeqCst));
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(handle.is_finished());
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::Timeout)
        ));
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn managed_task_handle_abort_defers_waker_until_cancel_lane_publication() {
        init_test("managed_task_handle_abort_defers_waker_until_cancel_lane_publication");
        exercise_managed_handle_cancel_boundary(false);
        crate::test_complete!(
            "managed_task_handle_abort_defers_waker_until_cancel_lane_publication"
        );
    }

    #[test]
    fn managed_join_future_drop_defers_waker_until_cancel_lane_publication() {
        init_test("managed_join_future_drop_defers_waker_until_cancel_lane_publication");
        exercise_managed_handle_cancel_boundary(true);
        crate::test_complete!(
            "managed_join_future_drop_defers_waker_until_cancel_lane_publication"
        );
    }

    #[test]
    fn checkpoint_ack_ready_before_handle_command_reconciles_terminal_cancel() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicU64, Ordering};

        init_test("checkpoint_ack_ready_before_handle_command_reconciles_terminal_cancel");
        let mut runtime = LabRuntime::new(LabConfig::new(19));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let entered = Arc::new(Barrier::new(2));
        let abort_done = Arc::new(Barrier::new(2));
        let auxiliary_calls = Arc::new(AtomicU64::new(0));
        let auxiliary_waker = Waker::from(Arc::new(CountWaker(Arc::clone(&auxiliary_calls))));

        let task_entered = Arc::clone(&entered);
        let task_abort_done = Arc::clone(&abort_done);
        let (task_id, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                std::future::poll_fn(move |_| {
                    crate::cx::Cx::with_current(|cx| {
                        cx.register_cancel_waker(&auxiliary_waker);
                    })
                    .expect("task Cx is installed");
                    task_entered.wait();
                    task_abort_done.wait();
                    assert!(
                        crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false),
                        "same-poll checkpoint observes the queued handle abort"
                    );
                    Poll::Ready(())
                })
                .await;
            })
            .expect("create managed task");
        runtime.scheduler.lock().schedule(task_id, 0);

        let canceller = std::thread::spawn(move || {
            let handle = handle;
            entered.wait();
            handle.abort_with_reason(CancelReason::race_loser());
            abort_done.wait();
            handle
        });

        runtime.step_for_test();
        let mut handle = canceller.join().expect("abort thread completes");
        assert!(
            !runtime.spawn_mailbox.handle_cancels_are_empty(),
            "command remains queued until the next runtime boundary"
        );
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::RaceLost)
        ));
        assert_eq!(
            auxiliary_calls.load(Ordering::SeqCst),
            1,
            "auxiliary cancellation Waker runs once after terminal publication"
        );
        assert!(handle.is_finished());
        assert!(
            !matches!(handle.try_join(), Ok(None)),
            "join result is available regardless of path-specific payload semantics"
        );

        runtime.step_for_test();
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::RaceLost)
        ));
        assert_eq!(auxiliary_calls.load(Ordering::SeqCst), 1);
        assert!(runtime.check_invariants().is_empty());
        crate::test_complete!(
            "checkpoint_ack_ready_before_handle_command_reconciles_terminal_cancel"
        );
    }

    #[test]
    fn checkpoint_ack_pending_republishes_cancel_lane_before_waker_dispatch() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        init_test("checkpoint_ack_pending_republishes_cancel_lane_before_waker_dispatch");
        let mut runtime = LabRuntime::new(LabConfig::new(23));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let entered = Arc::new(Barrier::new(2));
        let abort_done = Arc::new(Barrier::new(2));
        let polls = Arc::new(AtomicUsize::new(0));
        let audit_target = Arc::new(Mutex::new(None));
        let caller_lock = Arc::new(Mutex::new(()));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let calls_under_caller_lock = Arc::new(AtomicUsize::new(0));
        let calls_under_scheduler_lock = Arc::new(AtomicUsize::new(0));
        let cancel_lane_published = Arc::new(AtomicBool::new(false));

        let task_entered = Arc::clone(&entered);
        let task_abort_done = Arc::clone(&abort_done);
        let task_polls = Arc::clone(&polls);
        let task_audit_target = Arc::clone(&audit_target);
        let (task_id, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                std::future::poll_fn(move |_| {
                    let poll = task_polls.fetch_add(1, Ordering::SeqCst);
                    if poll == 0 {
                        let target = task_audit_target
                            .lock()
                            .as_ref()
                            .cloned()
                            .expect("audit Waker installed before first poll");
                        let retired = crate::cx::Cx::with_current(|cx| {
                            cx.inner.write().cancel_waker.replace(target)
                        })
                        .expect("task Cx is installed");
                        drop(retired);
                        task_entered.wait();
                        task_abort_done.wait();
                    }
                    assert!(
                        crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false),
                        "checkpoint observes cancellation on every cleanup poll"
                    );
                    if poll == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
            })
            .expect("create managed task");
        *audit_target.lock() = Some(Arc::new(crate::types::task_context::CancelWaker::new(
            Waker::from(Arc::new(HandleCancelWakeAudit {
                task_id,
                caller_lock: Arc::clone(&caller_lock),
                scheduler: Arc::clone(&runtime.scheduler),
                wake_calls: Arc::clone(&wake_calls),
                calls_under_caller_lock: Arc::clone(&calls_under_caller_lock),
                calls_under_scheduler_lock: Arc::clone(&calls_under_scheduler_lock),
                cancel_lane_published: Arc::clone(&cancel_lane_published),
            })),
        )));
        runtime.scheduler.lock().schedule(task_id, 0);

        let canceller = std::thread::spawn(move || {
            let handle = handle;
            entered.wait();
            handle.abort_with_reason(CancelReason::shutdown());
            abort_done.wait();
            handle
        });

        runtime.step_for_test();
        let handle = canceller.join().expect("abort thread completes");
        assert!(matches!(
            &runtime.state.task(task_id).expect("task record").state,
            TaskState::Cancelling { reason, .. } if reason.is_kind(CancelKind::Shutdown)
        ));
        assert!(
            !runtime.scheduler.lock().is_empty(),
            "acknowledged Pending task is republished on the cancel lane"
        );
        assert_eq!(
            wake_calls.load(Ordering::SeqCst),
            1,
            "first reconciliation dispatches the audit Waker once"
        );
        assert_eq!(calls_under_caller_lock.load(Ordering::SeqCst), 0);
        assert_eq!(calls_under_scheduler_lock.load(Ordering::SeqCst), 0);
        assert!(
            cancel_lane_published.load(Ordering::SeqCst),
            "the first Waker callback must observe an already-published cancel lane"
        );

        runtime.step_for_test();
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::Shutdown)
        ));
        assert_eq!(
            wake_calls.load(Ordering::SeqCst),
            1,
            "repeated acknowledged checkpoints do not duplicate Waker dispatch"
        );
        assert!(handle.is_finished());
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(runtime.check_invariants().is_empty());
        crate::test_complete!(
            "checkpoint_ack_pending_republishes_cancel_lane_before_waker_dispatch"
        );
    }

    #[test]
    fn handle_cancel_command_blocks_lab_quiescence_until_drained() {
        init_test("handle_cancel_command_blocks_lab_quiescence_until_drained");
        let mut runtime = LabRuntime::new(LabConfig::new(11));
        assert!(runtime.is_quiescent());

        let missing = TaskId::from_arena(ArenaIndex::new(usize::MAX as u32, 0));
        let gateway = runtime.state.spawn_gateway().expect("lab gateway");
        assert!(gateway.enqueue_handle_cancel(missing, CancelReason::shutdown()));
        assert!(
            !runtime.is_quiescent(),
            "a queued command is live runtime work even when its task is stale"
        );

        assert_eq!(runtime.run_until_quiescent(), 1);
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(runtime.is_quiescent());
        crate::test_complete!("handle_cancel_command_blocks_lab_quiescence_until_drained");
    }

    #[test]
    fn managed_pre_admission_abort_transitions_task_record_before_first_poll() {
        init_test("managed_pre_admission_abort_transitions_task_record_before_first_poll");
        let mut runtime = LabRuntime::new(LabConfig::new(13));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let pending = runtime
            .state
            .region(root)
            .expect("root region")
            .pending_spawn_handle();
        let parent: crate::cx::Cx = crate::cx::Cx::new(
            root,
            TaskId::from_arena(ArenaIndex::new(u32::MAX - 1, 0)),
            Budget::INFINITE,
        )
        .with_spawn_gateway(runtime.state.spawn_gateway())
        .with_pending_spawn_counter(Some(pending));

        let mut handle = parent
            .spawn(|child| async move {
                std::future::poll_fn(move |_| {
                    if child.checkpoint().is_err() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            })
            .expect("managed spawn enqueues");
        let provisional = handle.task_id();
        handle.abort_with_reason(CancelReason::race_loser());
        assert!(
            runtime.spawn_mailbox.handle_cancels_are_empty(),
            "pre-admission abort remains cache-only until identity publication"
        );

        assert_eq!(runtime.run_until_quiescent(), 1);
        let canonical = handle.task_id();
        assert_ne!(canonical, provisional);
        assert!(
            runtime.state.task(canonical).is_none(),
            "quiescent completion retires the canonical task record"
        );
        assert!(handle.is_finished());
        assert!(runtime.spawn_mailbox.is_empty());
        assert!(runtime.is_quiescent());
        assert!(matches!(
            handle.try_join(),
            Err(crate::runtime::JoinError::Cancelled(reason))
                if reason.is_kind(CancelKind::RaceLost)
        ));
        crate::test_complete!(
            "managed_pre_admission_abort_transitions_task_record_before_first_poll"
        );
    }

    #[test]
    fn stale_handle_cancel_command_cannot_weaken_newer_cx_reason() {
        init_test("stale_handle_cancel_command_cannot_weaken_newer_cx_reason");
        let mut runtime = LabRuntime::new(LabConfig::new(17));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create managed task");
        let inner = runtime
            .state
            .task(task_id)
            .and_then(|task| task.cx_inner.clone())
            .expect("managed task Cx");

        handle.abort_with_reason(CancelReason::user("stale"));
        let mut stale = Vec::new();
        assert_eq!(
            runtime
                .spawn_mailbox
                .dequeue_handle_cancels_into(1, &mut stale),
            1
        );
        handle.abort_with_reason(CancelReason::shutdown());
        let stale = stale.pop().expect("saved stale command");

        let (route, wakes) = runtime
            .state
            .cancel_task_for_handle(stale.task_id, &stale.reason)
            .into_parts();
        assert_eq!(route.map(|route| route.priority), Some(u8::MAX));
        assert!(route.is_some_and(|route| !route.delegated_initial));
        assert!(wakes.is_empty());
        wakes.dispatch();
        assert!(
            runtime
                .state
                .task(task_id)
                .and_then(TaskRecord::cancel_reason)
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown))
        );
        assert!(
            inner
                .read()
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown))
        );
        crate::test_complete!("stale_handle_cancel_command_cannot_weaken_newer_cx_reason");
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct TimerAdvanceOutcome {
        advance_points: Vec<Time>,
        total_wakeups: u64,
        final_time: Time,
        cancelled_wakeups: u64,
    }

    fn collect_timer_advances(
        deadlines_secs: &[u64],
        cancelled_indices: &[usize],
    ) -> TimerAdvanceOutcome {
        let mut runtime = LabRuntime::with_seed(42);
        let timer_handle = runtime.state.timer_driver_handle().expect("timer handle");
        let live_wakeups = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancelled_wakeups = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::with_capacity(deadlines_secs.len());

        for (idx, secs) in deadlines_secs.iter().copied().enumerate() {
            let counter = if cancelled_indices.contains(&idx) {
                cancelled_wakeups.clone()
            } else {
                live_wakeups.clone()
            };
            let waker = Waker::from(Arc::new(CountWaker(counter)));
            handles.push(timer_handle.register(Time::from_secs(secs), waker));
        }

        for &idx in cancelled_indices {
            let cancelled = timer_handle.cancel(&handles[idx]);
            crate::assert_with_log!(
                cancelled,
                "cancelled timer handle remains removable before auto-advance",
                true,
                cancelled
            );
        }

        let mut advance_points = Vec::new();
        while runtime.pending_timer_count() > 0 {
            let before = runtime.now();
            let next_deadline = runtime.next_timer_deadline().expect("pending deadline");
            let wakeups = runtime.advance_to_next_timer();
            let after = runtime.now();

            crate::assert_with_log!(
                after >= before,
                "virtual time stays monotone while advancing timers",
                true,
                after >= before
            );
            crate::assert_with_log!(
                after >= next_deadline,
                "advance reaches or passes scheduled deadline",
                true,
                after >= next_deadline
            );
            crate::assert_with_log!(
                wakeups > 0,
                "each advance drains at least one live timer",
                true,
                wakeups > 0
            );

            advance_points.push(after);
        }

        TimerAdvanceOutcome {
            advance_points,
            total_wakeups: live_wakeups.load(std::sync::atomic::Ordering::SeqCst),
            final_time: runtime.now(),
            cancelled_wakeups: cancelled_wakeups.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn empty_runtime_is_quiescent(runtime: &mut LabRuntime) {
        let quiescent = runtime.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn advance_time(runtime: &mut LabRuntime) {
        let now = runtime.now();
        crate::assert_with_log!(now == Time::ZERO, "now", Time::ZERO, now);

        runtime.advance_time(1_000_000);
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_millis(1),
            "now",
            Time::from_millis(1),
            now
        );
    }

    #[test]
    fn duration_nanos_saturating_clamps_large_duration() {
        init_test("duration_nanos_saturating_clamps_large_duration");
        let huge = Duration::from_secs(u64::MAX);
        let saturated = LabRuntime::duration_nanos_saturating(huge);
        crate::assert_with_log!(
            saturated == u64::MAX,
            "huge duration saturates",
            u64::MAX,
            saturated
        );

        let small = Duration::from_nanos(123);
        let exact = LabRuntime::duration_nanos_saturating(small);
        crate::assert_with_log!(exact == 123, "small duration exact", 123u64, exact);
        crate::test_complete!("duration_nanos_saturating_clamps_large_duration");
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_records_io_ready_trace() {
        init_test("lab_runtime_records_io_ready_trace");

        let mut runtime = LabRuntime::with_seed(42);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let waker = noop_waker();
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_millis(1));
        runtime.advance_time(1_000_000);
        runtime.step_for_test();

        let mut saw_requested = false;
        let mut saw_ready = false;
        for event in runtime.state.trace.snapshot() {
            if event.kind == TraceEventKind::IoRequested {
                saw_requested = true;
            }
            if event.kind == TraceEventKind::IoReady {
                saw_ready = true;
            }
        }
        crate::assert_with_log!(
            saw_requested,
            "io requested trace recorded",
            true,
            saw_requested
        );
        crate::assert_with_log!(saw_ready, "io ready trace recorded", true, saw_ready);
        crate::test_complete!("lab_runtime_records_io_ready_trace");
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_chaos_stats_include_reactor_io_error_injections() {
        init_test("lab_runtime_chaos_stats_include_reactor_io_error_injections");

        let config = LabConfig::new(7).with_chaos(
            ChaosConfig::new(7)
                .with_io_error_probability(1.0)
                .with_io_error_kinds(vec![std::io::ErrorKind::TimedOut]),
        );
        let mut runtime = LabRuntime::new(config);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let waker = noop_waker();
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::ZERO);
        runtime.step_for_test();

        let stats = runtime.chaos_stats();
        crate::assert_with_log!(
            stats.io_errors == 1,
            "io errors aggregated",
            1u64,
            stats.io_errors
        );
        crate::assert_with_log!(
            stats.decision_points == 1,
            "reactor decision points aggregated",
            1u64,
            stats.decision_points
        );
        crate::assert_with_log!(
            runtime.lab_reactor().last_io_error_kind() == Some(std::io::ErrorKind::TimedOut),
            "reactor last error kind surfaced",
            Some(std::io::ErrorKind::TimedOut),
            runtime.lab_reactor().last_io_error_kind()
        );

        crate::test_complete!("lab_runtime_chaos_stats_include_reactor_io_error_injections");
    }

    #[test]
    fn pending_task_without_wakeup_storm_still_counts_chaos_decision_point() {
        init_test("pending_task_without_wakeup_storm_still_counts_chaos_decision_point");

        let config =
            LabConfig::new(99).with_chaos(ChaosConfig::new(99).with_wakeup_storm_probability(0.0));
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        runtime.step_for_test();

        let stats = runtime.chaos_stats();
        crate::assert_with_log!(
            stats.decision_points == 2,
            "pending-task decision point counted",
            2u64,
            stats.decision_points
        );
        crate::assert_with_log!(
            stats.wakeup_storms == 0,
            "no wakeup storm recorded",
            0u64,
            stats.wakeup_storms
        );

        crate::test_complete!(
            "pending_task_without_wakeup_storm_still_counts_chaos_decision_point"
        );
    }

    #[test]
    fn pre_poll_multi_injection_counts_one_chaos_decision_point() {
        init_test("pre_poll_multi_injection_counts_one_chaos_decision_point");

        let config = LabConfig::new(123).with_chaos(
            ChaosConfig::new(123)
                .with_cancel_probability(1.0)
                .with_delay_probability(1.0)
                .with_delay_range(Duration::ZERO..Duration::from_nanos(2))
                .with_budget_exhaust_probability(1.0),
        );
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        runtime.step_for_test();

        let stats = runtime.chaos_stats();
        crate::assert_with_log!(
            stats.decision_points == 1,
            "multi-injection pre-poll counts once",
            1u64,
            stats.decision_points
        );
        crate::assert_with_log!(
            stats.cancellations == 1,
            "cancel recorded",
            1u64,
            stats.cancellations
        );
        crate::assert_with_log!(stats.delays == 1, "delay recorded", 1u64, stats.delays);
        crate::assert_with_log!(
            stats.budget_exhaustions == 1,
            "budget exhaust recorded",
            1u64,
            stats.budget_exhaustions
        );
        crate::assert_with_log!(
            stats.total_delay == Duration::from_nanos(1),
            "positive delay preserved",
            Duration::from_nanos(1),
            stats.total_delay
        );

        crate::test_complete!("pre_poll_multi_injection_counts_one_chaos_decision_point");
    }

    #[test]
    fn deterministic_rng() {
        init_test("deterministic_rng");
        let mut r1 = LabRuntime::with_seed(42);
        let mut r2 = LabRuntime::with_seed(42);

        let a = r1.rng.next_u64();
        let b = r2.rng.next_u64();
        crate::assert_with_log!(a == b, "rng", b, a);
        crate::test_complete!("deterministic_rng");
    }

    #[test]
    fn lab_scheduler_pop_for_worker_respects_timed_deadlines() {
        init_test("lab_scheduler_pop_for_worker_respects_timed_deadlines");
        let mut scheduler = LabScheduler::new(1, 0);
        let timed = TaskId::from_arena(ArenaIndex::new(1, 0));
        let ready = TaskId::from_arena(ArenaIndex::new(2, 0));

        scheduler.schedule_timed(timed, Time::from_nanos(100));
        scheduler.schedule(ready, 10);

        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((ready, DispatchLane::Ready)),
            "ready task dispatches before not-due timed task",
            Some((ready, DispatchLane::Ready)),
            first
        );

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second.is_none(),
            "future timed task stays queued before deadline",
            true,
            second.is_none()
        );

        let third = scheduler.pop_for_worker(0, 2, Time::from_nanos(100));
        crate::assert_with_log!(
            third == Some((timed, DispatchLane::Timed)),
            "timed task dispatches at deadline",
            Some((timed, DispatchLane::Timed)),
            third
        );

        crate::test_complete!("lab_scheduler_pop_for_worker_respects_timed_deadlines");
    }

    #[test]
    fn forced_cancel_dispatch_preserves_normal_fairness_state() {
        init_test("forced_cancel_dispatch_preserves_normal_fairness_state");
        let task = TaskId::from_arena(ArenaIndex::new(3, 0));
        let mut normal = LabScheduler::new(1, 0);
        let mut forced = LabScheduler::new(1, 0);

        normal.cancel_streak[0] = normal.cancel_streak_limit;
        forced.cancel_streak[0] = forced.cancel_streak_limit;
        normal.schedule_cancel(task, 10);
        forced.schedule_cancel(task, 10);

        assert_eq!(
            normal.pop_for_worker(0, 0, Time::ZERO),
            Some((task, DispatchLane::Cancel))
        );
        forced
            .take_forced(task, 0, DispatchLane::Cancel, Time::ZERO, 0)
            .expect("forced cancel dispatch must remain available");

        assert_eq!(normal.cancel_streak[0], 1);
        assert_eq!(forced.cancel_streak[0], normal.cancel_streak[0]);
        crate::test_complete!("forced_cancel_dispatch_preserves_normal_fairness_state");
    }

    #[test]
    fn lab_scheduler_steal_for_worker_only_steals_ready_tasks() {
        init_test("lab_scheduler_steal_for_worker_only_steals_ready_tasks");
        let mut scheduler = LabScheduler::new(2, 0);
        let cancel = TaskId::from_arena(ArenaIndex::new(10, 0));
        let timed = TaskId::from_arena(ArenaIndex::new(11, 0));
        let ready = TaskId::from_arena(ArenaIndex::new(12, 0));

        // With 2 workers, assignment is round-robin: cancel->w0, timed->w1, ready->w0.
        scheduler.schedule_cancel(cancel, 100);
        scheduler.schedule_timed(timed, Time::ZERO);
        scheduler.schedule(ready, 50);

        let stolen = scheduler.steal_for_worker(1, 0);
        crate::assert_with_log!(
            stolen == Some(ready),
            "steal path takes only ready lane work",
            Some(ready),
            stolen
        );

        crate::assert_with_log!(
            scheduler.workers[0].has_cancel_work(),
            "victim cancel lane remains intact after steal",
            true,
            scheduler.workers[0].has_cancel_work()
        );

        let cancel_dispatch = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            cancel_dispatch == Some((cancel, DispatchLane::Cancel)),
            "cancel lane still dispatches from victim worker",
            Some((cancel, DispatchLane::Cancel)),
            cancel_dispatch
        );

        let timed_dispatch = scheduler.pop_for_worker(1, 0, Time::ZERO);
        crate::assert_with_log!(
            timed_dispatch == Some((timed, DispatchLane::Timed)),
            "timed lane remains on owning worker",
            Some((timed, DispatchLane::Timed)),
            timed_dispatch
        );

        crate::test_complete!("lab_scheduler_steal_for_worker_only_steals_ready_tasks");
    }

    #[test]
    fn lab_scheduler_spurious_wakes_do_not_collapse_duplicates() {
        init_test("lab_scheduler_spurious_wakes_do_not_collapse_duplicates");
        let mut scheduler = LabScheduler::new(1, 0);
        let task = TaskId::from_arena(ArenaIndex::new(13, 0));

        scheduler.inject_spurious_wakes(task, 42, 3);

        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((task, DispatchLane::Ready)),
            "first spurious wake dispatches",
            Some((task, DispatchLane::Ready)),
            first
        );

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second == Some((task, DispatchLane::Ready)),
            "second spurious wake remains queued",
            Some((task, DispatchLane::Ready)),
            second
        );

        let third = scheduler.pop_for_worker(0, 2, Time::ZERO);
        crate::assert_with_log!(
            third == Some((task, DispatchLane::Ready)),
            "third spurious wake remains queued",
            Some((task, DispatchLane::Ready)),
            third
        );

        let fourth = scheduler.pop_for_worker(0, 3, Time::ZERO);
        crate::assert_with_log!(
            fourth.is_none(),
            "storm drains after requested wake count",
            true,
            fourth.is_none()
        );
        crate::assert_with_log!(
            scheduler.is_empty(),
            "scheduler empty after spurious storm drains",
            true,
            scheduler.is_empty()
        );

        crate::test_complete!("lab_scheduler_spurious_wakes_do_not_collapse_duplicates");
    }

    #[test]
    fn lab_scheduler_forget_task_clears_pending_spurious_wakes() {
        init_test("lab_scheduler_forget_task_clears_pending_spurious_wakes");
        let mut scheduler = LabScheduler::new(1, 0);
        let task = TaskId::from_arena(ArenaIndex::new(14, 0));

        scheduler.inject_spurious_wakes(task, 42, 3);
        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((task, DispatchLane::Ready)),
            "first spurious wake dispatches before forget",
            Some((task, DispatchLane::Ready)),
            first
        );

        scheduler.forget_task(task);

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second.is_none(),
            "forget_task drains queued spurious wakes",
            true,
            second.is_none()
        );
        crate::assert_with_log!(
            scheduler.pending_spurious_wakes.is_empty(),
            "forget_task clears pending spurious wake budget",
            true,
            scheduler.pending_spurious_wakes.is_empty()
        );
        crate::assert_with_log!(
            scheduler.is_empty(),
            "scheduler empty after forget_task",
            true,
            scheduler.is_empty()
        );

        crate::test_complete!("lab_scheduler_forget_task_clears_pending_spurious_wakes");
    }

    #[test]
    fn lab_scheduler_steal_preserves_pending_spurious_wakes() {
        init_test("lab_scheduler_steal_preserves_pending_spurious_wakes");
        let mut scheduler = LabScheduler::new(2, 0);
        let task = TaskId::from_arena(ArenaIndex::new(15, 0));

        scheduler.inject_spurious_wakes(task, 42, 3);

        let stolen = scheduler.steal_for_worker(1, 0);
        crate::assert_with_log!(
            stolen == Some(task),
            "steal dispatches first storm wake",
            Some(task),
            stolen
        );

        let second = scheduler.pop_for_worker(1, 1, Time::ZERO);
        crate::assert_with_log!(
            second == Some((task, DispatchLane::Ready)),
            "steal path re-arms second storm wake on thief worker",
            Some((task, DispatchLane::Ready)),
            second
        );

        let third = scheduler.pop_for_worker(1, 2, Time::ZERO);
        crate::assert_with_log!(
            third == Some((task, DispatchLane::Ready)),
            "steal path preserves final pending storm wake",
            Some((task, DispatchLane::Ready)),
            third
        );

        let fourth = scheduler.pop_for_worker(1, 3, Time::ZERO);
        crate::assert_with_log!(
            fourth.is_none(),
            "all stolen storm wakes drain after requested count",
            true,
            fourth.is_none()
        );
        crate::assert_with_log!(
            scheduler.is_empty(),
            "scheduler empty after stolen storm drains",
            true,
            scheduler.is_empty()
        );

        crate::test_complete!("lab_scheduler_steal_preserves_pending_spurious_wakes");
    }

    #[test]
    fn deterministic_multiworker_schedule() {
        init_test("deterministic_multiworker_schedule");
        let config = LabConfig::new(7).worker_count(4);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            runtime.run_until_quiescent();
        });

        crate::test_complete!("deterministic_multiworker_schedule");
    }

    #[test]
    fn run_until_quiescent_with_report_is_deterministic() {
        init_test("run_until_quiescent_with_report_is_deterministic");

        let config = LabConfig::new(123).worker_count(4).max_steps(10_000);
        let mut r1 = LabRuntime::new(config.clone());
        let mut r2 = LabRuntime::new(config);

        let setup = |runtime: &mut LabRuntime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
        };

        setup(&mut r1);
        setup(&mut r2);

        let rep1 = r1.run_until_quiescent_with_report();
        let rep2 = r2.run_until_quiescent_with_report();

        crate::assert_with_log!(rep1.quiescent, "quiescent", true, rep1.quiescent);
        crate::assert_with_log!(rep2.quiescent, "quiescent", true, rep2.quiescent);

        assert_eq!(rep1.trace_fingerprint, rep2.trace_fingerprint);
        assert_eq!(rep1.trace_certificate, rep2.trace_certificate);
        assert_eq!(rep1.oracle_report.to_json(), rep2.oracle_report.to_json());
        assert_eq!(rep1.invariant_violations, rep2.invariant_violations);

        crate::assert_with_log!(
            rep1.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep1.oracle_report.all_passed()
        );
        crate::assert_with_log!(
            rep2.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep2.oracle_report.all_passed()
        );

        crate::test_complete!("run_until_quiescent_with_report_is_deterministic");
    }

    #[test]
    fn deadline_monitor_emits_warning() {
        init_test("deadline_monitor_emits_warning");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::from_secs(0),
            warning_threshold_fraction: 1.0,
            checkpoint_timeout: Duration::from_secs(0),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_millis(10));

        let task_idx = runtime.state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            budget,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let mut inner = CxInner::new(root, task_id, budget);
        inner.checkpoint_state.last_checkpoint = None;
        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .set_cx_inner(Arc::new(RwLock::new(inner)));

        runtime.step();

        let warnings = warnings.lock();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.region_id == root,
            "region_id",
            root,
            warning.region_id
        );
        let ok = matches!(
            warning.reason,
            WarningReason::ApproachingDeadline | WarningReason::ApproachingDeadlineNoProgress
        );
        crate::assert_with_log!(ok, "reason", true, ok);
        drop(warnings);
        crate::test_complete!("deadline_monitor_emits_warning");
    }

    #[test]
    fn deadline_monitor_e2e_stuck_detection() {
        init_test("deadline_monitor_e2e_stuck_detection");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_secs(10));
        let (task_id, _handle) = runtime
            .state
            .create_task(root, budget, async {})
            .expect("create task");

        {
            let task = runtime.state.task_mut(task_id).unwrap();
            let cx = task.cx.as_ref().expect("task cx");
            cx.checkpoint_with("starting work").expect("checkpoint");
        }

        runtime.step();

        let warnings = warnings.lock();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.reason == WarningReason::NoProgress,
            "reason",
            WarningReason::NoProgress,
            warning.reason
        );
        crate::assert_with_log!(
            warning.last_checkpoint_message.as_deref() == Some("starting work"),
            "checkpoint message",
            Some("starting work"),
            warning.last_checkpoint_message.as_deref()
        );
        drop(warnings);
        crate::test_complete!("deadline_monitor_e2e_stuck_detection");
    }

    #[test]
    fn futurelock_emits_trace_event() {
        init_test("futurelock_emits_trace_event");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task.
        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        // Create a pending obligation held by that task.
        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        for _ in 0..4 {
            runtime.step();
        }

        let futurelock = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::FuturelockDetected)
            .expect("expected futurelock trace event");

        match &futurelock.data {
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                let idle_ok = *idle_steps > 3;
                crate::assert_with_log!(idle_ok, "idle_steps > 3", true, idle_ok);
                let ok = held.as_slice() == [(obl_id, ObligationKind::SendPermit)];
                crate::assert_with_log!(
                    ok,
                    "held",
                    &[(obl_id, ObligationKind::SendPermit)],
                    held.as_slice()
                );
            }
            other => panic!("unexpected trace data: {other:?}"),
        }
        crate::test_complete!("futurelock_emits_trace_event");
    }

    #[test]
    fn futurelock_display_includes_error_code() {
        init_test("futurelock_display_includes_error_code");
        let task = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = RegionId::from_arena(ArenaIndex::new(3, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(4, 0));
        let violation = InvariantViolation::Futurelock {
            task,
            region,
            idle_steps: 8,
            held: vec![obligation],
            last_checkpoint_message: Some("waiting on permit".to_string()),
        };

        let rendered = violation.to_string();
        let has_code = rendered.starts_with("[ASUP-E402] futurelock:");
        crate::assert_with_log!(has_code, "futurelock display error code", true, has_code);
        crate::assert_with_log!(
            rendered.contains("idle=8"),
            "futurelock display idle steps",
            true,
            rendered.contains("idle=8")
        );
        crate::assert_with_log!(
            rendered.contains("last_checkpoint=\"waiting on permit\""),
            "futurelock display checkpoint message",
            true,
            rendered.contains("last_checkpoint=\"waiting on permit\"")
        );
        crate::test_complete!("futurelock_display_includes_error_code");
    }

    #[test]
    fn obligation_leak_display_includes_error_code_and_owner_facts() {
        init_test("obligation_leak_display_includes_error_code_and_owner_facts");
        let task = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = RegionId::from_arena(ArenaIndex::new(3, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(4, 0));
        let violation = InvariantViolation::ObligationLeak {
            leaks: vec![ObligationLeak {
                obligation,
                kind: ObligationKind::SendPermit,
                holder: task,
                region,
            }],
        };

        let rendered = violation.to_string();
        let has_code = rendered.starts_with("[ASUP-E101] obligation leak:");
        crate::assert_with_log!(
            has_code,
            "obligation leak display error code",
            true,
            has_code
        );
        crate::assert_with_log!(
            rendered.contains("count=1"),
            "obligation leak display count",
            true,
            rendered.contains("count=1")
        );
        crate::assert_with_log!(
            rendered.contains("obligation="),
            "obligation leak display obligation id",
            true,
            rendered.contains("obligation=")
        );
        crate::assert_with_log!(
            rendered.contains("kind=SendPermit"),
            "obligation leak display kind",
            true,
            rendered.contains("kind=SendPermit")
        );
        crate::assert_with_log!(
            rendered.contains("holder="),
            "obligation leak display holder",
            true,
            rendered.contains("holder=")
        );
        crate::assert_with_log!(
            rendered.contains("region="),
            "obligation leak display region",
            true,
            rendered.contains("region=")
        );
        crate::test_complete!("obligation_leak_display_includes_error_code_and_owner_facts");
    }

    #[test]
    fn futurelock_panic_includes_last_checkpoint_message() {
        init_test("futurelock_panic_includes_last_checkpoint_message");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(1)
            .panic_on_futurelock(true);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        runtime
            .state
            .task(task_id)
            .expect("task")
            .cx
            .as_ref()
            .expect("task cx")
            .checkpoint_with("waiting on downstream permit")
            .expect("checkpoint");

        let _ = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for _ in 0..3 {
                runtime.step();
            }
        }));
        let payload = result.expect_err("futurelock should panic");
        let message = if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = payload.downcast_ref::<&str>() {
            (*message).to_string()
        } else {
            String::from("<non-string panic>")
        };

        crate::assert_with_log!(
            message.contains("[ASUP-E402] futurelock detected"),
            "futurelock panic error code",
            true,
            message.contains("[ASUP-E402] futurelock detected")
        );
        crate::assert_with_log!(
            message.contains("last_checkpoint=\"waiting on downstream permit\""),
            "futurelock panic checkpoint message",
            true,
            message.contains("last_checkpoint=\"waiting on downstream permit\"")
        );
        crate::assert_with_log!(
            message.contains("seed=42"),
            "futurelock panic seed",
            true,
            message.contains("seed=42")
        );
        crate::test_complete!("futurelock_panic_includes_last_checkpoint_message");
    }

    #[test]
    #[should_panic(expected = "[ASUP-E402] futurelock detected")]
    fn futurelock_can_panic() {
        init_test("futurelock_can_panic");
        let config = LabConfig::new(42).futurelock_max_idle_steps(1);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let _ = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        // Run enough steps to exceed threshold and trigger panic.
        for _ in 0..3 {
            runtime.step();
        }
    }

    /// Regression test: actively polled tasks must NOT be flagged as futurelocked.
    ///
    /// Before the fix, `mark_polled()` was never called from `step()`, so
    /// `last_polled_step` stayed at 0. After threshold+1 steps, even a
    /// task polled every single step would be falsely flagged.
    #[test]
    fn polled_task_not_flagged_as_futurelocked() {
        init_test("polled_task_not_flagged_as_futurelocked");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(5)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task with a stored future that always yields (Pending).
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                loop {
                    crate::runtime::yield_now::yield_now().await;
                }
            })
            .expect("create task");

        // Give the task a pending obligation so it's eligible for futurelock.
        let _obl = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        // Schedule and run well past the threshold.
        runtime.scheduler.lock().schedule(task_id, 0);
        for _ in 0..20 {
            runtime.step();
        }

        // The task was polled every step, so no futurelock should fire.
        let violations = runtime.futurelock_violations();
        crate::assert_with_log!(
            violations.is_empty(),
            "no futurelock for actively polled task",
            true,
            violations.is_empty()
        );
        crate::test_complete!("polled_task_not_flagged_as_futurelocked");
    }

    /// A task record that is never polled, so its idle count is the step count.
    fn never_polled_task(runtime: &mut LabRuntime, root: RegionId) -> TaskId {
        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;
        task_id
    }

    fn futurelocked(runtime: &LabRuntime) -> Vec<(TaskId, u64, Vec<ObligationId>)> {
        runtime
            .futurelock_violations()
            .into_iter()
            .map(|violation| match violation {
                InvariantViolation::Futurelock {
                    task,
                    idle_steps,
                    held,
                    ..
                } => (task, idle_steps, held),
                other => panic!("unexpected violation: {other:?}"),
            })
            .collect()
    }

    /// The per-step check groups obligations by holder in one pass
    /// (br-asupersync-bzict6). It must report what the task-by-task scan
    /// reported: the same tasks in task-table order, each with its pending
    /// obligations in obligation-table order.
    #[test]
    fn futurelock_scan_matches_the_task_by_task_scan() {
        init_test("futurelock_scan_matches_the_task_by_task_scan");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let [a, b, c, d] = std::array::from_fn(|_| never_polled_task(&mut runtime, root));

        // Obligations interleave their holders; b's only one is resolved and d
        // is polled just before the check.
        let mut obligation = |holder| {
            runtime
                .state
                .create_obligation(ObligationKind::SendPermit, holder, root, None)
                .expect("create obligation")
        };
        let c1 = obligation(c);
        let a1 = obligation(a);
        let c2 = obligation(c);
        let b1 = obligation(b);
        let _d1 = obligation(d);
        runtime
            .state
            .commit_obligation(b1)
            .expect("commit b's obligation");

        for _ in 0..5 {
            runtime.step();
        }
        runtime
            .state
            .task_mut(d)
            .unwrap()
            .mark_polled(runtime.steps);

        let threshold = runtime.config.futurelock_max_idle_steps;
        let task_by_task: Vec<_> = runtime
            .state
            .tasks_iter()
            .filter(|(_, task)| !task.state.is_terminal())
            .filter_map(|(_, task)| {
                let held: Vec<_> = runtime
                    .state
                    .obligations_iter()
                    .filter(|(_, o)| o.is_pending() && o.holder == task.id)
                    .map(|(_, o)| o.id)
                    .collect();
                let idle_steps = runtime.steps.saturating_sub(task.last_polled_step);
                (!held.is_empty() && idle_steps > threshold).then_some((task.id, idle_steps, held))
            })
            .collect();

        let actual = futurelocked(&runtime);
        crate::assert_with_log!(
            actual == task_by_task,
            "grouped scan equals task-by-task scan",
            task_by_task,
            actual
        );
        let expected = vec![(a, 5, vec![a1]), (c, 5, vec![c1, c2])];
        crate::assert_with_log!(actual == expected, "futurelocked tasks", expected, actual);
        crate::test_complete!("futurelock_scan_matches_the_task_by_task_scan");
    }

    /// Skipping the scan while the step count is within the threshold must
    /// not delay detection: a never-polled holder is reported on the first
    /// step past the threshold.
    #[test]
    fn futurelock_is_detected_on_the_first_step_past_the_threshold() {
        init_test("futurelock_is_detected_on_the_first_step_past_the_threshold");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let task = never_polled_task(&mut runtime, root);
        let held = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task, root, None)
            .expect("create obligation");

        for _ in 0..3 {
            runtime.step();
        }
        let at_threshold = futurelocked(&runtime);
        crate::assert_with_log!(
            at_threshold.is_empty(),
            "nothing at step 3",
            Vec::<(TaskId, u64, Vec<ObligationId>)>::new(),
            at_threshold
        );

        runtime.step();
        let past_threshold = futurelocked(&runtime);
        let expected = vec![(task, 4, vec![held])];
        crate::assert_with_log!(
            past_threshold == expected,
            "reported at step 4",
            expected,
            past_threshold
        );
        crate::test_complete!("futurelock_is_detected_on_the_first_step_past_the_threshold");
    }

    #[test]
    fn immediate_completion_marks_running_before_completion() {
        init_test("immediate_completion_marks_running_before_completion");
        let mut runtime = LabRuntime::new(LabConfig::new(42));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        runtime.run_until_quiescent();

        let protocol_ok = runtime.check_cancellation_protocol().is_ok();
        crate::assert_with_log!(
            runtime.is_quiescent(),
            "runtime reached quiescence after immediate completion",
            true,
            runtime.is_quiescent()
        );
        crate::assert_with_log!(
            protocol_ok,
            "cancellation oracle accepted Created -> Running -> Completed",
            true,
            protocol_ok
        );

        crate::test_complete!("immediate_completion_marks_running_before_completion");
    }

    #[test]
    fn obligation_leak_detected_when_holder_completed() {
        init_test("obligation_leak_detected_when_holder_completed");
        let mut runtime = LabRuntime::with_seed(7);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .unwrap();

        let violations = runtime.check_invariants();
        let mut found = false;
        for violation in violations {
            if let InvariantViolation::ObligationLeak { leaks } = violation {
                found = true;
                let len = leaks.len();
                crate::assert_with_log!(len == 1, "leaks len", 1, len);
                let leak = &leaks[0];
                crate::assert_with_log!(
                    leak.obligation == obl_id,
                    "obligation",
                    obl_id,
                    leak.obligation
                );
                crate::assert_with_log!(
                    leak.kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    leak.kind
                );
                crate::assert_with_log!(leak.holder == task_id, "holder", task_id, leak.holder);
                crate::assert_with_log!(leak.region == root, "region", root, leak.region);
            }
        }
        crate::assert_with_log!(found, "found leak", true, found);
        crate::test_complete!("obligation_leak_detected_when_holder_completed");
    }

    #[test]
    fn obligation_leak_ignored_when_resolved() {
        init_test("obligation_leak_ignored_when_resolved");
        let mut runtime = LabRuntime::with_seed(11);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl_id)
            .expect("commit obligation");

        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .unwrap();

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(!has_leak, "no leak", false, has_leak);
        crate::test_complete!("obligation_leak_ignored_when_resolved");
    }

    #[test]
    fn report_hydrates_temporal_oracles_from_state_snapshot() {
        init_test("report_hydrates_temporal_oracles_from_state_snapshot");
        let mut runtime = LabRuntime::with_seed(31);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (_task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Force-close the region while a task is still live to simulate a
        // temporal invariant break that must be surfaced by report hydration.
        runtime
            .state
            .region(root)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closed);

        let report = runtime.report();
        let task_leak = report
            .oracle_report
            .entry("task_leak")
            .expect("task_leak entry");
        let quiescence = report
            .oracle_report
            .entry("quiescence")
            .expect("quiescence entry");

        crate::assert_with_log!(
            !task_leak.passed,
            "task_leak failed",
            false,
            task_leak.passed
        );
        crate::assert_with_log!(
            !quiescence.passed,
            "quiescence failed",
            false,
            quiescence.passed
        );
        let has_temporal_tag = report
            .invariant_violations
            .iter()
            .any(|v| v == "temporal:task_leak");
        crate::assert_with_log!(
            has_temporal_tag,
            "temporal marker present",
            true,
            has_temporal_tag
        );
        let temporal_failed = report
            .temporal_invariant_failures
            .iter()
            .any(|v| v == "task_leak");
        crate::assert_with_log!(
            temporal_failed,
            "temporal failure surfaced",
            true,
            temporal_failed
        );
        crate::test_complete!("report_hydrates_temporal_oracles_from_state_snapshot");
    }

    #[test]
    fn report_hydrates_quiescence_from_finalizers_and_obligations() {
        init_test("report_hydrates_quiescence_from_finalizers_and_obligations");
        let mut runtime = LabRuntime::with_seed(32);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        runtime.state.now = Time::from_nanos(10);
        let registered = runtime.state.register_sync_finalizer(root, || {});
        crate::assert_with_log!(registered, "registered finalizer", true, registered);

        runtime.state.now = Time::from_nanos(20);
        let _obligation = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        runtime.state.now = Time::from_nanos(30);
        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .expect("complete task without auto-resolving obligation");

        runtime.state.now = Time::from_nanos(40);
        runtime.state.record_finalizer_close_for_test(root);
        runtime
            .state
            .region(root)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closed);

        let report = runtime.report();
        let quiescence = report
            .oracle_report
            .entry("quiescence")
            .expect("quiescence entry");
        let finalizer = report
            .oracle_report
            .entry("finalizer")
            .expect("finalizer entry");
        let obligation_leak = report
            .oracle_report
            .entry("obligation_leak")
            .expect("obligation entry");

        crate::assert_with_log!(
            !quiescence.passed,
            "quiescence failed",
            false,
            quiescence.passed
        );
        let quiescence_text = quiescence
            .violation
            .as_deref()
            .expect("quiescence violation text");
        crate::assert_with_log!(
            quiescence_text.contains("1 unrun finalizers"),
            "quiescence mentions finalizers",
            true,
            quiescence_text.contains("1 unrun finalizers")
        );
        crate::assert_with_log!(
            quiescence_text.contains("1 leaked obligations"),
            "quiescence mentions obligations",
            true,
            quiescence_text.contains("1 leaked obligations")
        );
        crate::assert_with_log!(
            !finalizer.passed,
            "finalizer failed",
            false,
            finalizer.passed
        );
        crate::assert_with_log!(
            !obligation_leak.passed,
            "obligation_leak failed",
            false,
            obligation_leak.passed
        );
        for failed in report.oracle_report.failures() {
            let marker = format!("oracle:{}", failed.invariant);
            crate::assert_with_log!(
                report.invariant_violations.contains(&marker),
                "every failed oracle has aggregate marker",
                true,
                report.invariant_violations.contains(&marker)
            );
        }
        crate::test_complete!("report_hydrates_quiescence_from_finalizers_and_obligations");
    }

    #[test]
    fn report_hydrates_cancellation_propagation_from_state_snapshot() {
        init_test("report_hydrates_cancellation_propagation_from_state_snapshot");
        // This test intentionally drives a cancellation-propagation violation
        // to verify it surfaces in the temporal report. Default configs panic
        // on such violations during `report()`, so the oracle must be allowed
        // to merely *record* the violation instead of aborting the test.
        let config = LabConfig::new(32).panic_on_cancellation_violation(false);
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let _child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child");

        runtime
            .state
            .region(root)
            .expect("root exists")
            .cancel_request(crate::types::CancelReason::shutdown());

        let report = runtime.report();
        let cancellation = report
            .oracle_report
            .entry("cancellation_protocol")
            .expect("cancellation_protocol entry");
        crate::assert_with_log!(
            !cancellation.passed,
            "cancellation_protocol failed",
            false,
            cancellation.passed
        );
        let has_temporal_tag = report
            .invariant_violations
            .iter()
            .any(|v| v == "temporal:cancellation_protocol");
        crate::assert_with_log!(
            has_temporal_tag,
            "temporal cancellation marker present",
            true,
            has_temporal_tag
        );
        crate::test_complete!("report_hydrates_cancellation_propagation_from_state_snapshot");
    }

    /// The same propagation failure after a task has run. The lab feeds the
    /// cancellation_protocol oracle live task events, and once it had any,
    /// report() no longer read the region tree from the state, so the
    /// uncancelled child passed (br-asupersync-vcu2oz).
    #[test]
    fn report_checks_cancellation_propagation_after_a_task_has_run() {
        init_test("report_checks_cancellation_propagation_after_a_task_has_run");
        let config = LabConfig::new(32).panic_on_cancellation_violation(false);
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime.run_until_idle();
        let fed_live = runtime.oracles.cancellation_protocol.has_observed_events();
        crate::assert_with_log!(
            fed_live,
            "the polled task fed the oracle live",
            true,
            fed_live
        );

        let _child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child");
        runtime
            .state
            .region(root)
            .expect("root exists")
            .cancel_request(crate::types::CancelReason::shutdown());

        let report = runtime.report();
        let cancellation = report
            .oracle_report
            .entry("cancellation_protocol")
            .expect("cancellation_protocol entry");
        crate::assert_with_log!(
            !cancellation.passed,
            "a cancelled region with an uncancelled child fails after live events",
            false,
            cancellation.passed
        );
        crate::test_complete!("report_checks_cancellation_propagation_after_a_task_has_run");
    }

    #[test]
    fn report_surfaces_refinement_firewall_violation_from_trace_snapshot() {
        init_test("report_surfaces_refinement_firewall_violation_from_trace_snapshot");
        let mut runtime = LabRuntime::with_seed(33);
        let region = RegionId::new_for_test(41, 0);
        let task = TaskId::new_for_test(7, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(2, Time::ZERO, task, region));

        let report = runtime.report();
        crate::assert_with_log!(
            report.refinement_firewall_rule_id.as_deref() == Some("RFW-SPAWN-001"),
            "refinement rule id surfaced",
            Some("RFW-SPAWN-001"),
            report.refinement_firewall_rule_id.as_deref()
        );
        crate::assert_with_log!(
            report.refinement_firewall_event_index == Some(1),
            "refinement event index surfaced",
            Some(1usize),
            report.refinement_firewall_event_index
        );
        crate::assert_with_log!(
            report.refinement_counterexample_prefix_len == Some(2),
            "refinement prefix len surfaced",
            Some(2usize),
            report.refinement_counterexample_prefix_len
        );
        let has_marker = report
            .invariant_violations
            .iter()
            .any(|v| v == "refinement_firewall:RFW-SPAWN-001");
        crate::assert_with_log!(
            has_marker,
            "refinement invariant marker present",
            true,
            has_marker
        );
        let json = report.to_json();
        crate::assert_with_log!(
            json["refinement_firewall"]["rule_id"] == "RFW-SPAWN-001",
            "refinement json rule id",
            "RFW-SPAWN-001",
            json["refinement_firewall"]["rule_id"]
        );
        crate::assert_with_log!(
            json["refinement_firewall"]["counterexample_prefix_len"] == 2,
            "refinement json prefix len",
            2,
            json["refinement_firewall"]["counterexample_prefix_len"]
        );
        crate::assert_with_log!(
            json["refinement_firewall"]["skipped_due_to_trace_truncation"] == false,
            "refinement json not skipped",
            false,
            json["refinement_firewall"]["skipped_due_to_trace_truncation"]
        );
        crate::test_complete!("report_surfaces_refinement_firewall_violation_from_trace_snapshot");
    }

    // br-asupersync-9ri7x0: trace truncation no longer silently
    // disables the refinement-firewall oracle. The flag remains set
    // (it is part of the report contract) and the rule_id is None
    // because the firewall did not run, but the scenario must now
    // surface a hard 'scenario_failed_due_to_trace_truncation'
    // invariant_violations entry so any caller that gates on
    // invariant_violations.is_empty() will fail loudly. The seed and
    // truncation watermark are embedded in the message so an
    // operator can immediately bump trace_capacity or split the
    // scenario.
    #[test]
    fn report_fails_loudly_when_trace_buffer_is_truncated_l9ri7x0() {
        init_test("report_fails_loudly_when_trace_buffer_is_truncated_l9ri7x0");
        let seed = 35;
        let config = LabConfig::new(seed).trace_capacity(1);
        let mut runtime = LabRuntime::new(config);
        let region = RegionId::new_for_test(43, 0);
        let task = TaskId::new_for_test(9, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::complete(2, Time::ZERO, task, region));

        let report = runtime.report();
        crate::assert_with_log!(
            report.refinement_firewall_skipped_due_to_trace_truncation,
            "refinement_firewall_skipped_due_to_trace_truncation",
            true,
            report.refinement_firewall_skipped_due_to_trace_truncation
        );
        crate::assert_with_log!(
            report.refinement_firewall_rule_id.is_none(),
            "no real rule_id when firewall could not run",
            true,
            report.refinement_firewall_rule_id.is_none()
        );

        // The new contract: invariant_violations MUST contain a
        // hard-fail marker that names the truncation cause + seed +
        // watermark. The substring is checked rather than equality
        // so future format adjustments stay backward-compatible.
        let truncation_marker = report
            .invariant_violations
            .iter()
            .find(|v| v.starts_with("refinement_firewall:scenario_failed_due_to_trace_truncation"));
        let marker = truncation_marker.expect(
            "truncation must surface as a hard refinement_firewall:scenario_failed_due_to_trace_truncation marker",
        );
        assert!(
            marker.contains(&format!("seed={seed}")),
            "truncation marker must embed the seed, got: {marker}"
        );
        assert!(
            marker.contains("total_pushed=") && marker.contains("buffered="),
            "truncation marker must embed total_pushed + buffered watermark, got: {marker}"
        );
        // And of course the scenario must NOT report 'passed':
        // invariant_violations.is_empty() is the standard pass gate.
        crate::assert_with_log!(
            !report.invariant_violations.is_empty(),
            "scenario must fail loudly when trace buffer truncates",
            true,
            !report.invariant_violations.is_empty()
        );

        let json = report.to_json();
        crate::assert_with_log!(
            json["refinement_firewall"]["skipped_due_to_trace_truncation"] == true,
            "skipped flag still serialized for downstream tooling",
            true,
            json["refinement_firewall"]["skipped_due_to_trace_truncation"]
        );
        crate::test_complete!("report_fails_loudly_when_trace_buffer_is_truncated_l9ri7x0");
    }

    // br-asupersync-7uu7sa: chaos-injected wakeup_storm must be
    // suppressed when the targeted task's owning region has already
    // transitioned to Closing/Draining/Closed. Drives the inner
    // method directly, then drives it again after flipping the
    // owning region's state to Closing — the second call must NOT
    // schedule the task.
    #[test]
    fn inject_spurious_wakes_suppressed_when_owning_region_is_closing_l7uu7sa() {
        init_test("inject_spurious_wakes_suppressed_when_owning_region_is_closing_l7uu7sa");

        let mut runtime = LabRuntime::with_seed(42);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let task_idx = runtime.state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        // Region is Open: the inner method must schedule the task.
        runtime.inject_spurious_wakes(task_id, 0, 2);
        let scheduled_open = {
            let mut sched = runtime.scheduler.lock();
            let mut count = 0u32;
            while sched.pop_for_worker(0, count.into(), Time::ZERO).is_some() {
                count += 1;
            }
            count
        };
        crate::assert_with_log!(
            scheduled_open == 2,
            "while region is Open, 2 spurious wakes are scheduled",
            2u32,
            scheduled_open
        );

        // Transition the region into a non-accepting state.
        runtime
            .state
            .region(region)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closing);

        // Now the call must be silently suppressed — no work on the queue.
        runtime.inject_spurious_wakes(task_id, 0, 5);
        let scheduled_closing = {
            let mut sched = runtime.scheduler.lock();
            let mut count = 0u32;
            while sched.pop_for_worker(0, count.into(), Time::ZERO).is_some() {
                count += 1;
            }
            count
        };
        crate::assert_with_log!(
            scheduled_closing == 0,
            "after region.set_state(Closing), spurious wakes are suppressed",
            0u32,
            scheduled_closing
        );

        // Defense-in-depth: walk every other terminal-ish state.
        for state in [
            crate::record::region::RegionState::Draining,
            crate::record::region::RegionState::Closed,
        ] {
            runtime
                .state
                .region(region)
                .expect("region exists")
                .set_state(state);
            runtime.inject_spurious_wakes(task_id, 0, 3);
            let scheduled = {
                let mut sched = runtime.scheduler.lock();
                let mut count = 0u32;
                while sched.pop_for_worker(0, count.into(), Time::ZERO).is_some() {
                    count += 1;
                }
                count
            };
            assert_eq!(
                scheduled, 0,
                "spurious wakes must be suppressed in region state {state:?}"
            );
        }

        crate::test_complete!(
            "inject_spurious_wakes_suppressed_when_owning_region_is_closing_l7uu7sa"
        );
    }

    #[test]
    fn crashpack_includes_refinement_firewall_markers() {
        init_test("crashpack_includes_refinement_firewall_markers");
        let mut runtime = LabRuntime::with_seed(34);
        let region = RegionId::new_for_test(42, 0);
        let task = TaskId::new_for_test(8, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(2, Time::ZERO, task, region));

        let run = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&run)
            .expect("refinement-firewall failure should build crashpack");
        let has_rule_marker = crashpack
            .oracle_violations
            .iter()
            .any(|entry| entry == "refinement_firewall:RFW-SPAWN-001");
        crate::assert_with_log!(
            has_rule_marker,
            "crashpack includes refinement rule marker",
            true,
            has_rule_marker
        );
        let has_prefix_marker = crashpack
            .oracle_violations
            .iter()
            .any(|entry| entry == "refinement_firewall:minimal_counterexample_prefix_len=2");
        crate::assert_with_log!(
            has_prefix_marker,
            "crashpack includes refinement prefix marker",
            true,
            has_prefix_marker
        );
        crate::test_complete!("crashpack_includes_refinement_firewall_markers");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn obligation_trace_events_emitted() {
        init_test("obligation_trace_events_emitted");
        let mut runtime = LabRuntime::with_seed(21);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(10));
        let ob1 = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(25));
        runtime.state.commit_obligation(ob1).unwrap();

        runtime.advance_time_to(Time::from_nanos(30));
        let ob2 = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(50));
        runtime
            .state
            .abort_obligation(ob2, ObligationAbortReason::Cancel)
            .unwrap();

        let commit_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationCommit)
            .expect("commit event");
        match &commit_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*obligation == ob1, "obligation", ob1, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Committed,
                    "state",
                    crate::record::ObligationState::Committed,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(15),
                    "duration",
                    &Some(15),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected commit data: {other:?}"),
        }

        let abort_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*obligation == ob2, "obligation", ob2, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Ack,
                    "kind",
                    ObligationKind::Ack,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Aborted,
                    "state",
                    crate::record::ObligationState::Aborted,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(20),
                    "duration",
                    &Some(20),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason == &Some(ObligationAbortReason::Cancel),
                    "abort_reason",
                    &Some(ObligationAbortReason::Cancel),
                    abort_reason
                );
            }
            other => panic!("unexpected abort data: {other:?}"),
        }
        crate::test_complete!("obligation_trace_events_emitted");
    }

    #[test]
    fn obligation_leak_emits_trace_event() {
        init_test("obligation_leak_emits_trace_event");
        let mut runtime = LabRuntime::with_seed(22);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(100));
        let obligation = runtime
            .state
            .create_obligation(ObligationKind::Lease, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(140));
        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .unwrap();

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(has_leak, "has leak", true, has_leak);

        let leak_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationLeak)
            .expect("leak event");
        match &leak_event.data {
            TraceData::Obligation {
                obligation: leaked,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*leaked == obligation, "obligation", obligation, *leaked);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Lease,
                    "kind",
                    ObligationKind::Lease,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Leaked,
                    "state",
                    crate::record::ObligationState::Leaked,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(40),
                    "duration",
                    &Some(40),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected leak data: {other:?}"),
        }
        crate::test_complete!("obligation_leak_emits_trace_event");
    }

    // =========================================================================
    // Agent Report Contract tests (bd-f262i)
    // =========================================================================

    /// The JSON schema must contain all required top-level keys.
    #[test]
    fn contract_json_has_required_top_level_keys() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_json_has_required_top_level_keys");

        let app = crate::app::AppSpec::new("contract_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();
        let json = report.to_json();

        // Required top-level keys per bd-f262i contract.
        let required_keys = [
            "schema_version",
            "verdict",
            "app",
            "lab",
            "fingerprints",
            "run",
            "crashpack",
            "attachments",
        ];
        for key in &required_keys {
            assert!(
                json.get(key).is_some(),
                "missing required top-level key: {key}"
            );
        }

        // Nested required keys.
        assert!(json["app"]["name"].is_string(), "app.name must be a string");
        assert!(
            json["lab"]["config"].is_object(),
            "lab.config must be an object"
        );
        assert!(
            json["lab"]["config_hash"].is_u64(),
            "lab.config_hash must be a u64"
        );
        assert!(
            json["fingerprints"]["trace"].is_u64(),
            "fingerprints.trace must be a u64"
        );
        assert!(
            json["fingerprints"]["event_hash"].is_u64(),
            "fingerprints.event_hash must be a u64"
        );
        assert!(
            json["fingerprints"]["event_count"].is_u64(),
            "fingerprints.event_count must be a u64"
        );
        assert!(
            json["fingerprints"]["schedule_hash"].is_u64(),
            "fingerprints.schedule_hash must be a u64"
        );
        assert!(json["run"]["seed"].is_u64(), "run.seed must be a u64");
        assert!(
            json["run"]["oracles"].is_object(),
            "run.oracles must be an object"
        );
        assert!(
            json["run"]["invariants"].is_array(),
            "run.invariants must be an array"
        );
        assert!(
            json["run"]["refinement_firewall"].is_object(),
            "run.refinement_firewall must be an object"
        );
        assert!(
            json["run"]["refinement_firewall"]["skipped_due_to_trace_truncation"].is_boolean(),
            "run.refinement_firewall.skipped_due_to_trace_truncation must be a boolean"
        );
        assert!(
            json["attachments"].is_array(),
            "attachments must be an array"
        );
        assert!(
            json["crashpack"].is_null(),
            "passing runs should have null crashpack linkage"
        );

        crate::test_complete!("contract_json_has_required_top_level_keys");
    }

    /// Schema version must be the current constant.
    #[test]
    fn contract_schema_version_is_current() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_schema_version_is_current");

        let app = crate::app::AppSpec::new("version_test");
        let harness = crate::lab::SporkAppHarness::with_seed(1, app).unwrap();
        let report = harness.run_to_report().unwrap();

        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        assert_eq!(
            report.to_json()["schema_version"],
            SporkHarnessReport::SCHEMA_VERSION
        );

        crate::test_complete!("contract_schema_version_is_current");
    }

    /// Config hash is deterministic: same config -> same hash.
    #[test]
    fn contract_config_hash_deterministic() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_config_hash_deterministic");

        let config = LabConfig::new(42);
        let summary_a = LabConfigSummary::from_config(&config);
        let summary_b = LabConfigSummary::from_config(&config);

        assert_eq!(summary_a.config_hash(), summary_b.config_hash());

        // Different seed -> different hash.
        let config_2 = LabConfig::new(99);
        let summary_c = LabConfigSummary::from_config(&config_2);
        assert_ne!(summary_a.config_hash(), summary_c.config_hash());

        crate::test_complete!("contract_config_hash_deterministic");
    }

    /// Verdict field correctly reflects pass/fail.
    #[test]
    fn contract_verdict_reflects_oracle_state() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_verdict_reflects_oracle_state");

        let app = crate::app::AppSpec::new("verdict_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();

        // Empty app should pass.
        assert!(report.passed());
        assert_eq!(report.to_json()["verdict"], "pass");
        assert!(report.summary_line().starts_with("[PASS]"));

        let mut truncated = report.clone();
        truncated.run.quiescent = false;
        assert!(!truncated.passed());
        assert_eq!(truncated.to_json()["verdict"], "fail");
        assert!(truncated.summary_line().starts_with("[FAIL]"));
        let runtime = LabRuntime::with_seed(42);
        assert!(runtime.build_crashpack_for_report(&truncated.run).is_some());

        crate::test_complete!("contract_verdict_reflects_oracle_state");
    }

    #[test]
    fn crashpack_prefers_failed_terminal_task_over_live_task() {
        init_test("crashpack_prefers_failed_terminal_task_over_live_task");
        let mut runtime = LabRuntime::with_seed(0x4b_78);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let live_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let live_task = TaskId::from_arena(live_idx);
        runtime.state.task_mut(live_task).unwrap().id = live_task;

        let failed_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let failed_task = TaskId::from_arena(failed_idx);
        runtime.state.task_mut(failed_task).unwrap().id = failed_task;
        runtime
            .state
            .update_task(failed_task, |record| {
                record.complete(Outcome::Panicked(crate::types::PanicPayload::new(
                    "intentional crashpack attribution panic",
                )))
            })
            .expect("complete failed task");

        let report = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&report)
            .expect("live task should make the report fail");
        assert_eq!(crashpack.failure.task, failed_task);
        assert_eq!(crashpack.failure.region, root);
        assert!(matches!(
            crashpack.failure.outcome,
            FailureOutcome::Panicked { ref message }
                if message == "intentional crashpack attribution panic"
        ));
        crate::test_complete!("crashpack_prefers_failed_terminal_task_over_live_task");
    }

    #[test]
    fn crashpack_preserves_cancelled_terminal_task_kind() {
        init_test("crashpack_preserves_cancelled_terminal_task_kind");
        let mut runtime = LabRuntime::with_seed(0x4b_79);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let live_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let live_task = TaskId::from_arena(live_idx);
        runtime.state.task_mut(live_task).unwrap().id = live_task;

        let cancelled_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let cancelled_task = TaskId::from_arena(cancelled_idx);
        runtime.state.task_mut(cancelled_task).unwrap().id = cancelled_task;
        runtime
            .state
            .update_task(cancelled_task, |record| {
                record.complete(Outcome::Cancelled(crate::types::CancelReason::timeout()))
            })
            .expect("complete cancelled task");

        let report = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&report)
            .expect("live task should make the report fail");
        assert_eq!(crashpack.failure.task, cancelled_task);
        assert_eq!(crashpack.failure.region, root);
        assert_eq!(
            crashpack.failure.outcome,
            FailureOutcome::Cancelled {
                cancel_kind: crate::types::CancelKind::Timeout,
            }
        );
        crate::test_complete!("crashpack_preserves_cancelled_terminal_task_kind");
    }

    const PLAIN_RUNNER_FAILURE_PROBE: &str = "lab::runtime::tests::plain_runner_failure_probe";
    const PLAIN_RUNNER_FAILURE_SEED: u64 = 0x4b78_0003;

    fn trigger_plain_runner_failure_probe() {
        panic!("intentional plain-runner failure probe"); // ubs:ignore — deliberate subprocess failure injection in a test-only helper
    }

    #[test]
    #[ignore = "subprocess-only probe for plain-runner crashpack emission"]
    fn plain_runner_failure_probe() {
        if std::env::var_os(PLAIN_RUNNER_FAILURE_PROBE_ENV).is_none() {
            return;
        }
        let _ = run_async_under_lab(PLAIN_RUNNER_FAILURE_SEED, |_cx| async move {
            trigger_plain_runner_failure_probe();
        });
    }

    #[test]
    fn plain_runner_failure_writes_crashpack() {
        init_test("plain_runner_failure_writes_crashpack");
        let now = std::time::SystemTime::now(); // ubs:ignore — test-directory uniqueness only, not a security token
        let nonce = now
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let artifact_root = std::env::temp_dir().join(format!(
            "asupersync-fgdb-4bxh-{}-{nonce}",
            std::process::id()
        ));
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--ignored",
                "--exact",
                PLAIN_RUNNER_FAILURE_PROBE,
                "--nocapture",
            ])
            .env(AUTO_ARTIFACTS_ENV, "1")
            .env(TEST_ARTIFACTS_DIR_ENV, &artifact_root)
            .env(PLAIN_RUNNER_FAILURE_PROBE_ENV, "1")
            .env_remove(LAB_TEST_SEED_ENV)
            .env_remove(LAB_TEST_WORKERS_ENV)
            .env_remove(LAB_TEST_MAX_STEPS_ENV)
            .output()
            .expect("run plain-runner failure probe");
        assert!(!output.status.success(), "failure probe must fail");

        let mut transcript = String::from_utf8_lossy(&output.stdout).into_owned();
        transcript.push_str(&String::from_utf8_lossy(&output.stderr));
        assert!(
            transcript.contains(&format!("seed {PLAIN_RUNNER_FAILURE_SEED}")),
            "failure transcript must name the replay seed: {transcript}"
        );
        let crashpack_path = transcript
            .lines()
            .find_map(|line| line.trim().strip_prefix("crashpack: "))
            .expect("failure transcript must name the crashpack path");
        assert!(
            std::path::Path::new(crashpack_path).is_file(),
            "crashpack path must exist: {crashpack_path}"
        );
        let crashpack_json = std::fs::read_to_string(crashpack_path)
            .expect("plain-runner crashpack must be readable");
        let crashpack: serde_json::Value =
            serde_json::from_str(&crashpack_json).expect("plain-runner crashpack JSON");
        assert_eq!(
            crashpack["manifest"]["config"]["seed"],
            PLAIN_RUNNER_FAILURE_SEED
        );
        assert_eq!(
            crashpack["failure"]["outcome"]["Panicked"]["message"].as_str(),
            Some("intentional plain-runner failure probe")
        );
        crate::test_complete!("plain_runner_failure_writes_crashpack");
    }

    #[test]
    fn join_error_crashpack_outcome_preserves_kind_and_payload() {
        init_test("join_error_crashpack_outcome_preserves_kind_and_payload");
        let cancelled = crate::runtime::JoinError::Cancelled(crate::types::CancelReason::timeout());
        assert_eq!(
            failure_outcome_from_join_error(&cancelled),
            FailureOutcome::Cancelled {
                cancel_kind: crate::types::CancelKind::Timeout,
            }
        );

        let panicked = crate::runtime::JoinError::Panicked(crate::types::PanicPayload::new(
            "exact panic payload",
        ));
        assert_eq!(
            failure_outcome_from_join_error(&panicked),
            FailureOutcome::Panicked {
                message: "exact panic payload".to_owned(),
            }
        );
        crate::test_complete!("join_error_crashpack_outcome_preserves_kind_and_payload");
    }

    /// Agent UX convenience methods return consistent values.
    #[test]
    fn contract_convenience_methods_consistent() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_convenience_methods_consistent");

        let app = crate::app::AppSpec::new("ux_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();
        let json = report.to_json();

        // trace_fingerprint() matches JSON.
        assert_eq!(
            report.trace_fingerprint(),
            json["fingerprints"]["trace"].as_u64().unwrap()
        );

        // seed() matches JSON.
        assert_eq!(report.seed(), json["run"]["seed"].as_u64().unwrap());

        // config_hash() matches JSON.
        assert_eq!(
            report.config_hash(),
            json["lab"]["config_hash"].as_u64().unwrap()
        );

        // No crashpack by default.
        assert!(report.crashpack_path().is_none());

        // Empty app -> no oracle failures.
        assert!(report.oracle_failures().is_empty());

        crate::test_complete!("contract_convenience_methods_consistent");
    }

    /// Failing runs auto-attach a deterministic crashpack reference.
    #[test]
    fn contract_auto_crashpack_on_failure() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_auto_crashpack_on_failure");

        let config = LabConfig::new(17).panic_on_leak(false);
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        // Create the obligation while the task is still live, then run to
        // quiescence so the task completes without resolving it (intentional leak).
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");
        runtime.run_until_quiescent();

        let report = runtime.spork_report("failing_app", Vec::new());
        assert!(!report.passed(), "failing run must not report PASS");
        let crashpack_path = report
            .crashpack_path()
            .expect("failing run should include crashpack attachment");
        assert!(
            crashpack_path.starts_with("crashpack-"),
            "unexpected crashpack path: {crashpack_path}"
        );
        assert!(
            report
                .attachments
                .iter()
                .any(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack),
            "crashpack attachment kind must be present"
        );
        let crashpack_link = report
            .crashpack_link()
            .expect("failing run should expose crashpack link metadata");
        assert_eq!(crashpack_link.path, crashpack_path);
        assert_eq!(crashpack_link.fingerprint, report.trace_fingerprint());
        assert!(
            crashpack_link.id.starts_with("crashpack-"),
            "unexpected crashpack id: {}",
            crashpack_link.id
        );
        assert!(
            crashpack_link.replay.command_line.contains(crashpack_path),
            "replay command should include crashpack path"
        );

        crate::test_complete!("contract_auto_crashpack_on_failure");
    }

    /// Failing runs with replay recording enabled include a deterministic
    /// divergent prefix in the auto-built crashpack.
    #[test]
    fn contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled");

        let config = LabConfig::new(1701)
            .panic_on_leak(false)
            .with_default_replay_recording();
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");
        runtime.run_until_quiescent();

        let run = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&run)
            .expect("failing run should build crashpack");

        assert!(crashpack.has_divergent_prefix());
        assert!(
            crashpack
                .manifest
                .has_attachment(&crate::trace::crashpack::AttachmentKind::DivergentPrefix),
            "manifest must include divergent prefix attachment"
        );
        assert!(
            crashpack.replay.is_some(),
            "crashpack should carry replay command metadata"
        );

        crate::test_complete!(
            "contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled"
        );
    }

    /// Manual crashpack attachments are preserved without auto-duplication.
    #[test]
    fn contract_manual_crashpack_not_duplicated_on_failure() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_manual_crashpack_not_duplicated_on_failure");

        let config = LabConfig::new(18).panic_on_leak(false);
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");
        runtime.run_until_quiescent();

        let report = runtime.spork_report(
            "failing_app_manual",
            vec![HarnessAttachmentRef::crashpack("manual-crashpack.json")],
        );
        let crashpack_count = report
            .attachments
            .iter()
            .filter(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack)
            .count();
        assert_eq!(
            crashpack_count, 1,
            "manual crashpack should not be duplicated"
        );
        assert_eq!(report.crashpack_path(), Some("manual-crashpack.json"));
        let crashpack_link = report
            .crashpack_link()
            .expect("manual crashpack should still produce metadata");
        assert_eq!(crashpack_link.path, "manual-crashpack.json");
        assert!(
            crashpack_link
                .replay
                .command_line
                .contains("manual-crashpack.json"),
            "replay command should include manual crashpack path"
        );

        crate::test_complete!("contract_manual_crashpack_not_duplicated_on_failure");
    }

    /// JSON output is deterministic across runs with same seed.
    #[test]
    fn contract_json_deterministic_same_seed() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_json_deterministic_same_seed");

        let json_a = {
            let app = crate::app::AppSpec::new("det_contract");
            let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap().to_json()
        };

        let json_b = {
            let app = crate::app::AppSpec::new("det_contract");
            let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap().to_json()
        };

        // The canonical Foata `trace_fingerprint` is the semantic determinism
        // signal. The sequential `event_hash` additionally embeds per-event
        // data (e.g. ephemeral IDs allocated from process-global counters)
        // that benignly drifts across invocations in the same process even
        // for the same seed. Normalise it before comparing so the assertion
        // targets what the test actually contracts for ("same seed →
        // equivalent run artefact") rather than incidental monotonic counters.
        fn strip_event_hash(obj: &mut serde_json::Map<String, serde_json::Value>) {
            if obj.contains_key("event_hash") {
                obj.insert("event_hash".into(), serde_json::Value::Null);
            }
            for val in obj.values_mut() {
                if let Some(sub) = val.as_object_mut() {
                    strip_event_hash(sub);
                }
            }
        }
        let normalize = |mut v: serde_json::Value| -> serde_json::Value {
            if let Some(obj) = v.as_object_mut() {
                strip_event_hash(obj);
            }
            v
        };

        assert_eq!(
            normalize(json_a),
            normalize(json_b),
            "same seed must produce identical JSON (mod sequential event_hash)",
        );

        crate::test_complete!("contract_json_deterministic_same_seed");
    }

    /// Attachments appear in the report, sorted by (kind, path).
    #[test]
    fn contract_attachments_sorted_in_json() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_attachments_sorted_in_json");

        let app = crate::app::AppSpec::new("attach_contract");
        let mut harness = crate::lab::SporkAppHarness::with_seed(7, app).unwrap();
        // Add in reverse order to verify sorting.
        harness.attach(HarnessAttachmentRef::trace("z_trace.json"));
        harness.attach(HarnessAttachmentRef::crashpack("a_crash.tar"));

        let report = harness.run_to_report().unwrap();

        // crashpack_path() returns the crashpack.
        assert_eq!(report.crashpack_path(), Some("a_crash.tar"));

        let json = report.to_json();
        let attachments = json["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);

        // CrashPack sorts before Trace (enum ordering).
        assert_eq!(attachments[0]["kind"], "crashpack");
        assert_eq!(attachments[1]["kind"], "trace");

        crate::test_complete!("contract_attachments_sorted_in_json");
    }

    // =========================================================================
    // Virtual Time Control Tests (bd-1hu19.3)
    // =========================================================================

    #[asupersync::lab_test(seeds = 42..43)]
    fn advance_to_next_timer_empty(runtime: &mut LabRuntime) {
        let wakeups = runtime.advance_to_next_timer();
        crate::assert_with_log!(wakeups == 0, "no timers → 0 wakeups", 0, wakeups);

        let deadline = runtime.next_timer_deadline();
        crate::assert_with_log!(
            deadline.is_none(),
            "no pending deadline",
            true,
            deadline.is_none()
        );
    }

    #[test]
    fn advance_to_next_timer_fires_timer() {
        init_test("advance_to_next_timer_fires_timer");
        let mut runtime = LabRuntime::with_seed(42);

        // Register a timer at t=1s via the timer driver handle
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let woken = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let waker = Waker::from(Arc::new(FlagWaker(woken.clone())));
        let _ = timer_handle.register(Time::from_secs(1), waker);

        // Should have 1 pending timer
        let count = runtime.pending_timer_count();
        crate::assert_with_log!(count == 1, "1 pending timer", 1, count);

        // Advance to next timer
        let wakeups = runtime.advance_to_next_timer();
        crate::assert_with_log!(wakeups == 1, "1 wakeup", 1, wakeups);

        // Time should now be at 1 second
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "time at 1s",
            Time::from_secs(1),
            now
        );

        // Waker should have been called
        let was_woken = woken.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(was_woken, "waker fired", true, was_woken);
        crate::test_complete!("advance_to_next_timer_fires_timer");
    }

    #[test]
    fn metamorphic_timer_registration_permutation_preserves_virtual_time_progression() {
        init_test("metamorphic_timer_registration_permutation_preserves_virtual_time_progression");

        let baseline = collect_timer_advances(&[5, 1, 3, 1, 8], &[]);
        let permuted = collect_timer_advances(&[1, 8, 5, 1, 3], &[]);

        crate::assert_with_log!(
            baseline.advance_points == permuted.advance_points,
            "deadline multiset permutation preserves advance points",
            &baseline.advance_points,
            &permuted.advance_points
        );
        crate::assert_with_log!(
            baseline.total_wakeups == permuted.total_wakeups,
            "deadline multiset permutation preserves wakeup count",
            baseline.total_wakeups,
            permuted.total_wakeups
        );
        crate::assert_with_log!(
            baseline.final_time == permuted.final_time,
            "deadline multiset permutation preserves final virtual time",
            baseline.final_time,
            permuted.final_time
        );
        crate::assert_with_log!(
            baseline.advance_points
                == vec![
                    Time::from_secs(1),
                    Time::from_secs(3),
                    Time::from_secs(5),
                    Time::from_secs(8)
                ],
            "advance points collapse duplicate deadlines without moving backward",
            vec![
                Time::from_secs(1),
                Time::from_secs(3),
                Time::from_secs(5),
                Time::from_secs(8)
            ],
            baseline.advance_points.clone()
        );

        crate::test_complete!(
            "metamorphic_timer_registration_permutation_preserves_virtual_time_progression"
        );
    }

    #[test]
    fn metamorphic_cancelled_timer_does_not_skew_virtual_time_progression() {
        init_test("metamorphic_cancelled_timer_does_not_skew_virtual_time_progression");

        let baseline = collect_timer_advances(&[2, 4, 9], &[]);
        let with_cancelled_timer = collect_timer_advances(&[2, 4, 6, 9], &[2]);

        crate::assert_with_log!(
            baseline.advance_points == with_cancelled_timer.advance_points,
            "cancelling an intermediate timer preserves surviving advance points",
            &baseline.advance_points,
            &with_cancelled_timer.advance_points
        );
        crate::assert_with_log!(
            baseline.total_wakeups == with_cancelled_timer.total_wakeups,
            "cancelling an intermediate timer preserves surviving wakeup count",
            baseline.total_wakeups,
            with_cancelled_timer.total_wakeups
        );
        crate::assert_with_log!(
            baseline.final_time == with_cancelled_timer.final_time,
            "cancelling an intermediate timer preserves final virtual time",
            baseline.final_time,
            with_cancelled_timer.final_time
        );
        crate::assert_with_log!(
            with_cancelled_timer.cancelled_wakeups == 0,
            "cancelled timer never wakes after auto-advance",
            0u64,
            with_cancelled_timer.cancelled_wakeups
        );

        crate::test_complete!("metamorphic_cancelled_timer_does_not_skew_virtual_time_progression");
    }

    #[cfg(unix)]
    #[test]
    fn run_with_auto_advance_delivers_delayed_reactor_events() {
        init_test("run_with_auto_advance_delivers_delayed_reactor_events");
        let config = LabConfig::new(42).with_auto_advance().max_steps(32);
        let mut runtime = LabRuntime::new(config);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_secs(1));

        let report = runtime.run_with_auto_advance();

        crate::assert_with_log!(
            report.auto_advances >= 1,
            "auto-advance reaches delayed reactor deadline",
            true,
            report.auto_advances >= 1
        );
        crate::assert_with_log!(
            runtime.now() >= Time::from_secs(1),
            "virtual time advanced to delayed reactor event",
            true,
            runtime.now() >= Time::from_secs(1)
        );
        let wakeups = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(
            wakeups == 1,
            "reactor event woke registration",
            1u64,
            wakeups
        );
        let saw_ready = runtime
            .state
            .trace
            .snapshot()
            .iter()
            .any(|event| event.kind == TraceEventKind::IoReady);
        crate::assert_with_log!(saw_ready, "io ready trace recorded", true, saw_ready);
        let next_event = runtime.lab_reactor().next_event_time();
        crate::assert_with_log!(
            next_event.is_none(),
            "delayed reactor event drained",
            true,
            next_event.is_none()
        );

        crate::test_complete!("run_with_auto_advance_delivers_delayed_reactor_events");
    }

    #[test]
    fn run_with_auto_advance_basic() {
        init_test("run_with_auto_advance_basic");
        let config = LabConfig::new(42).with_auto_advance();
        let mut runtime = LabRuntime::new(config);

        // No tasks, no timers → immediate quiescence
        let report = runtime.run_with_auto_advance();
        crate::assert_with_log!(report.steps == 0, "0 steps", 0u64, report.steps);
        crate::assert_with_log!(
            report.auto_advances == 0,
            "0 auto-advances",
            0u64,
            report.auto_advances
        );
        crate::test_complete!("run_with_auto_advance_basic");
    }

    #[test]
    fn run_with_auto_advance_jumps_past_timer_deadlines() {
        init_test("run_with_auto_advance_jumps_past_timer_deadlines");
        let config = LabConfig::new(42).with_auto_advance().max_steps(1_000);
        let mut runtime = LabRuntime::new(config);

        // Register timers at 1s, 5s, and 10s via timer driver
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for secs in [1, 5, 10] {
            let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
            let _ = timer_handle.register(Time::from_secs(secs), waker);
        }

        let report = runtime.run_with_auto_advance();

        // All 3 timer deadlines should have been auto-advanced to
        crate::assert_with_log!(
            report.auto_advances >= 3,
            "at least 3 auto-advances",
            true,
            report.auto_advances >= 3
        );

        // Virtual time should be at or past 10 seconds
        let now = runtime.now();
        crate::assert_with_log!(
            now >= Time::from_secs(10),
            "time >= 10s",
            true,
            now >= Time::from_secs(10)
        );

        // All wakers should have been called
        let count = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "3 wakeups", 3u64, count);
        crate::test_complete!("run_with_auto_advance_jumps_past_timer_deadlines");
    }

    #[test]
    fn virtual_time_24_hour_instant_test() {
        init_test("virtual_time_24_hour_instant_test");
        // Acceptance criterion: 24 hours of virtual time in <1 second wall time.
        let config = LabConfig::new(42).with_auto_advance().max_steps(100_000);
        let mut runtime = LabRuntime::new(config);

        // Register timers spread across 24 hours (every hour)
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for hour in 1..=24 {
            let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
            let _ = timer_handle.register(Time::from_secs(hour * 3600), waker);
        }

        let wall_start = std::time::Instant::now();
        let report = runtime.run_with_auto_advance();
        let wall_elapsed = wall_start.elapsed();

        // Virtual time should span 24 hours = 86400 seconds
        crate::assert_with_log!(
            report.virtual_elapsed_secs() >= 86400,
            "24h virtual",
            true,
            report.virtual_elapsed_secs() >= 86400
        );

        // All 24 timers fired
        let count = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(count == 24, "24 wakeups", 24u64, count);

        // Wall time should be well under 1 second (typically <1ms)
        let wall_ms = wall_elapsed.as_millis();
        crate::assert_with_log!(wall_ms < 1000, "wall time < 1s", true, wall_ms < 1000);
        crate::test_complete!("virtual_time_24_hour_instant_test");
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn clock_pause_resume(runtime: &mut LabRuntime) {
        let not_paused = !runtime.is_clock_paused();
        crate::assert_with_log!(not_paused, "not paused initially", true, not_paused);

        runtime.pause_clock();
        let paused = runtime.is_clock_paused();
        crate::assert_with_log!(paused, "paused", true, paused);

        runtime.resume_clock();
        let resumed = !runtime.is_clock_paused();
        crate::assert_with_log!(resumed, "resumed", true, resumed);
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn inject_clock_skew(runtime: &mut LabRuntime) {
        runtime.advance_time(1_000_000_000); // 1 second
        let before = runtime.now();

        // Inject 5 second skew
        runtime.inject_clock_skew(5_000_000_000);
        let after = runtime.now();

        let delta = after.as_nanos() - before.as_nanos();
        crate::assert_with_log!(
            delta == 5_000_000_000,
            "5s skew applied",
            5_000_000_000u64,
            delta
        );

        crate::assert_with_log!(
            after == Time::from_secs(6),
            "time at 6s",
            Time::from_secs(6),
            after
        );
    }

    #[test]
    fn virtual_time_report_conversions() {
        init_test("virtual_time_report_conversions");
        let report = VirtualTimeReport {
            steps: 100,
            auto_advances: 5,
            total_wakeups: 10,
            time_start: Time::ZERO,
            time_end: Time::from_secs(3600),
            virtual_elapsed_nanos: 3_600_000_000_000,
            termination: AutoAdvanceTermination::Quiescent,
        };

        let ms = report.virtual_elapsed_ms();
        crate::assert_with_log!(ms == 3_600_000, "3600000 ms", 3_600_000u64, ms);

        let secs = report.virtual_elapsed_secs();
        crate::assert_with_log!(secs == 3600, "3600 secs", 3600u64, secs);
        crate::test_complete!("virtual_time_report_conversions");
    }

    // =========================================================================
    // Replay severity correctness (bd-beuyd)
    // =========================================================================

    /// Completes once `flag` is set; parks its waker otherwise so only the
    /// setter's explicit wake makes the task runnable again.
    struct WaitForFlag {
        flag: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl std::future::Future for WaitForFlag {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.flag.load(std::sync::atomic::Ordering::Acquire) {
                std::task::Poll::Ready(())
            } else {
                *self.waker.lock() = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }

    /// Two tasks with a real dependency (br-asupersync-bi2462.7).
    ///
    /// `A` (spawn ordinal 0) observes 0, yields, then sets the flag, wakes
    /// `B` and observes 10; `B` (ordinal 1) observes 1, waits for the flag
    /// and observes 11. `B`'s second poll is only runnable after `A`'s
    /// second.
    fn production_replay_fixture(
        config: LabConfig,
        observations: Arc<Mutex<Vec<u8>>>,
    ) -> LabRuntime {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let flag = Arc::new(AtomicBool::new(false));
        let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));

        let task_a = {
            let observations = Arc::clone(&observations);
            let flag = Arc::clone(&flag);
            let waker = Arc::clone(&waker);
            let (task, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    observations.lock().push(0);
                    futures_lite::future::yield_now().await;
                    flag.store(true, Ordering::Release);
                    if let Some(waker) = waker.lock().take() {
                        waker.wake();
                    }
                    observations.lock().push(10);
                })
                .expect("create production-replay task A");
            task
        };
        let task_b = {
            let observations = Arc::clone(&observations);
            let (task, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    observations.lock().push(1);
                    WaitForFlag { flag, waker }.await;
                    observations.lock().push(11);
                })
                .expect("create production-replay task B");
            task
        };
        runtime.scheduler.lock().schedule(task_a, 0);
        runtime.scheduler.lock().schedule(task_b, 1);
        runtime
    }

    fn production_replay_config(seed: u64) -> LabConfig {
        LabConfig::new(seed)
            .with_default_replay_recording()
            .max_steps(256)
    }

    /// The fixture's spawn events (ordinals 0 and 1) plus the root region,
    /// so a test can hand-craft a poll order.
    fn production_replay_spawns(source: &LabRuntime) -> (Vec<TraceEvent>, RegionId) {
        let events = source
            .recorded_production_trace_events()
            .expect("recording enabled");
        let spawns: Vec<TraceEvent> = events
            .iter()
            .filter(|event| event.kind == TraceEventKind::Spawn)
            .cloned()
            .collect();
        assert_eq!(spawns.len(), 2, "fixture spawns exactly two tasks");
        let region = match &spawns[0].data {
            TraceData::Task { region, .. } => *region,
            other => panic!("spawn event carries task data, got {other:?}"),
        };
        (spawns, region)
    }

    fn spawn_task_id(event: &TraceEvent) -> TaskId {
        match &event.data {
            TraceData::Task { task, .. } => *task,
            other => panic!("spawn event carries task data, got {other:?}"),
        }
    }

    #[test]
    fn production_replay_of_a_lab_recording_matches_every_step() {
        init_test("production_replay_of_a_lab_recording_matches_every_step");
        let config = production_replay_config(0xB2_0001);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source =
            production_replay_fixture(config.clone(), Arc::clone(&source_observations));
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .recorded_production_schedule()
            .expect("recording projects into a schedule");
        assert_eq!(schedule.spawn_order().len(), 2);
        // Either A1 B1 A2 B2 (four polls) or A1 A2 B1 (B sees the flag on
        // its first poll): the lab's own RNG decides, the recording keeps it.
        let recorded_steps = schedule.summary().steps;
        assert!(
            matches!(recorded_steps, 3 | 4),
            "unexpected recorded step count {recorded_steps}"
        );
        assert_eq!(source_observations.lock().len(), 4);

        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = production_replay_fixture(config, Arc::clone(&replay_observations));
        replay
            .replay_production_schedule(&schedule, ProductionReplayOptions::default())
            .expect("configure before the first step");
        assert!(replay.run_until_quiescent_with_report().quiescent);

        let report = replay.replay_report().expect("replay configured");
        assert_eq!(report.divergence, None);
        assert_eq!(report.steps_matched, recorded_steps);
        assert_eq!(report.steps_total, recorded_steps);
        assert_eq!(report.spawns_bound, 2);
        assert!(!report.stopped);
        assert_eq!(*replay_observations.lock(), *source_observations.lock());
        crate::test_complete!("production_replay_of_a_lab_recording_matches_every_step");
    }

    #[test]
    fn production_replay_rejects_configuration_after_the_first_step() {
        init_test("production_replay_rejects_configuration_after_the_first_step");
        let config = production_replay_config(0xB2_0002);
        let mut source =
            production_replay_fixture(config.clone(), Arc::new(Mutex::new(Vec::new())));
        source.run_until_quiescent();
        let schedule = source.recorded_production_schedule().expect("schedule");

        let mut late = production_replay_fixture(config, Arc::new(Mutex::new(Vec::new())));
        late.step();
        assert_eq!(
            late.replay_production_schedule(&schedule, ProductionReplayOptions::default()),
            Err(ProductionReplayError::AlreadyStarted { steps: 1 })
        );
        crate::test_complete!("production_replay_rejects_configuration_after_the_first_step");
    }

    #[test]
    fn production_replay_diverges_at_the_step_that_is_not_runnable() {
        init_test("production_replay_diverges_at_the_step_that_is_not_runnable");
        let config = production_replay_config(0xB2_0003);
        let mut source =
            production_replay_fixture(config.clone(), Arc::new(Mutex::new(Vec::new())));
        source.run_until_quiescent();
        let (spawns, region) = production_replay_spawns(&source);
        let task_a = spawn_task_id(&spawns[0]);
        let task_b = spawn_task_id(&spawns[1]);

        // Hand-swapped order: B twice before A ever runs. B's second poll
        // needs A's wake, so the schedule cannot be followed at index 1.
        let mut events = spawns;
        let base_seq = events.last().map_or(0, |event| event.seq) + 1;
        for (offset, task) in [task_b, task_b, task_a, task_a].into_iter().enumerate() {
            events.push(TraceEvent::poll(
                base_seq + offset as u64,
                Time::ZERO,
                task,
                region,
            ));
        }
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        assert_eq!(schedule.summary().steps, 4);

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = production_replay_fixture(config, Arc::clone(&observations));
        replay
            .replay_production_schedule(&schedule, ProductionReplayOptions::default())
            .expect("configure");
        replay.run_until_quiescent();

        let report = replay.replay_report().expect("replay configured");
        let divergence = report
            .divergence
            .clone()
            .expect("swapped step must diverge");
        assert_eq!(divergence.schedule_index, 1);
        assert_eq!(divergence.expected_ordinal, 1);
        assert_eq!(divergence.expected, Some(schedule.spawn_order()[1]));
        assert!(
            divergence.actual.is_some(),
            "ordinal 1 is bound to lab task B"
        );
        assert!(
            matches!(
                divergence.reason,
                ReplayDivergenceReason::TaskNotRunnable { .. }
            ),
            "{divergence:?}"
        );
        assert_eq!(report.steps_matched, 1);
        assert!(report.stopped, "Stop policy halts dispatch");
        assert_eq!(
            *observations.lock(),
            vec![1],
            "only B's first poll ran before the stop"
        );
        assert!(!replay.is_quiescent(), "the stopped run left work behind");
        crate::test_complete!("production_replay_diverges_at_the_step_that_is_not_runnable");
    }

    #[test]
    fn production_replay_reports_a_task_that_is_never_spawned() {
        init_test("production_replay_reports_a_task_that_is_never_spawned");
        let config = production_replay_config(0xB2_0004);
        let mut source =
            production_replay_fixture(config.clone(), Arc::new(Mutex::new(Vec::new())));
        source.run_until_quiescent();
        let (spawns, region) = production_replay_spawns(&source);
        let task_a = spawn_task_id(&spawns[0]);

        let mut events = spawns;
        let mut seq = events.last().map_or(0, |event| event.seq) + 1;
        let phantom = TaskId::from_arena(ArenaIndex::new(77, 1));
        events.push(TraceEvent::spawn(seq, Time::ZERO, phantom, region));
        seq += 1;
        events.push(TraceEvent::poll(seq, Time::ZERO, task_a, region));
        seq += 1;
        events.push(TraceEvent::poll(seq, Time::ZERO, phantom, region));
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        assert_eq!(schedule.spawn_order().len(), 3);

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = production_replay_fixture(config, Arc::clone(&observations));
        replay
            .replay_production_schedule(&schedule, ProductionReplayOptions::default())
            .expect("configure");
        replay.run_until_quiescent();

        let report = replay.replay_report().expect("replay configured");
        let divergence = report
            .divergence
            .clone()
            .expect("phantom task must diverge");
        assert_eq!(divergence.schedule_index, 1);
        assert_eq!(divergence.expected_ordinal, 2);
        assert_eq!(divergence.actual, None);
        assert_eq!(divergence.reason, ReplayDivergenceReason::TaskNeverSpawned);
        assert_eq!(report.steps_matched, 1);
        assert_eq!(report.spawns_bound, 2, "only the two real tasks bound");
        assert!(report.stopped);
        assert_eq!(*observations.lock(), vec![0]);
        crate::test_complete!("production_replay_reports_a_task_that_is_never_spawned");
    }

    #[test]
    fn production_replay_continue_mode_finishes_and_keeps_the_first_divergence() {
        init_test("production_replay_continue_mode_finishes_and_keeps_the_first_divergence");
        let config = production_replay_config(0xB2_0005);
        let mut source =
            production_replay_fixture(config.clone(), Arc::new(Mutex::new(Vec::new())));
        source.run_until_quiescent();
        let (spawns, region) = production_replay_spawns(&source);
        let task_a = spawn_task_id(&spawns[0]);
        let task_b = spawn_task_id(&spawns[1]);

        let mut events = spawns;
        let base_seq = events.last().map_or(0, |event| event.seq) + 1;
        for (offset, task) in [task_b, task_b, task_a, task_a].into_iter().enumerate() {
            events.push(TraceEvent::poll(
                base_seq + offset as u64,
                Time::ZERO,
                task,
                region,
            ));
        }
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = production_replay_fixture(config, Arc::clone(&observations));
        replay
            .replay_production_schedule(
                &schedule,
                ProductionReplayOptions {
                    on_divergence: OnReplayDivergence::Continue,
                    max_wait_steps: 8,
                },
            )
            .expect("configure");
        assert!(replay.run_until_quiescent_with_report().quiescent);

        let report = replay.replay_report().expect("replay configured");
        let divergence = report.divergence.clone().expect("first divergence is kept");
        assert_eq!(divergence.schedule_index, 1);
        assert!(matches!(
            divergence.reason,
            ReplayDivergenceReason::TaskNotRunnable { waited: 8 }
        ));
        assert_eq!(report.steps_matched, 1);
        assert!(!report.stopped);
        // B's first poll was replayed; the normal policy then ran A twice
        // (waking B) and B's second poll finished the run.
        assert_eq!(*observations.lock(), vec![1, 0, 10, 11]);
        crate::test_complete!(
            "production_replay_continue_mode_finishes_and_keeps_the_first_divergence"
        );
    }

    fn forced_schedule_fixture(config: LabConfig, observations: Arc<Mutex<Vec<u8>>>) -> LabRuntime {
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        for label in 0..3u8 {
            let observations = Arc::clone(&observations);
            let (task, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    observations.lock().push(label);
                    futures_lite::future::yield_now().await;
                    observations.lock().push(label + 10);
                })
                .expect("create forced-schedule fixture task");
            runtime.scheduler.lock().schedule(task, label);
        }
        runtime
    }

    #[test]
    fn forced_schedule_artifact_codec_is_canonical_bounded_and_replayable() {
        init_test("forced_schedule_artifact_codec_is_canonical_bounded_and_replayable");

        fn rewrite_checksum(bytes: &mut [u8]) {
            let checksum_offset = bytes
                .len()
                .checked_sub(FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN)
                .expect("canonical artifact contains checksum");
            let checksum = forced_schedule_artifact_checksum(&bytes[..checksum_offset]);
            bytes[checksum_offset..].copy_from_slice(&checksum);
        }

        fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        let config = LabConfig::new(0xF0CE_D5CE).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(32)
            .expect("start complete dispatch capture");
        let source_report = source.run_until_quiescent_with_report();
        assert!(source_report.quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete source schedule");
        assert_eq!(schedule.dispatches().len(), 6);

        let canonical = schedule
            .to_canonical_bytes()
            .expect("encode complete source schedule");
        let decoded_dispatch_bytes = std::mem::size_of_val(schedule.dispatches());
        let decode_limits =
            ForcedScheduleDecodeLimits::new(canonical.len(), 32, decoded_dispatch_bytes);
        assert_eq!(
            canonical.len(),
            FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
                + 6 * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN
                + FORCED_SCHEDULE_ARTIFACT_TERMINAL_LEN
                + FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN
        );
        let decoded = ForcedSchedule::try_from_canonical_bytes(&canonical, decode_limits)
            .expect("decode canonical schedule");
        assert_eq!(decoded, schedule);
        assert_eq!(
            decoded.to_canonical_bytes().expect("re-encode schedule"),
            canonical,
            "encode-decode-encode must be byte-identical"
        );
        for (decoded_dispatch, source_dispatch) in
            decoded.dispatches().iter().zip(schedule.dispatches())
        {
            assert_eq!(decoded_dispatch.task(), source_dispatch.task());
            assert_eq!(decoded_dispatch.worker(), source_dispatch.worker());
            assert_eq!(decoded_dispatch.lane(), source_dispatch.lane());
            assert_eq!(decoded_dispatch.at_step(), source_dispatch.at_step());
            assert_eq!(decoded_dispatch.at_nanos(), source_dispatch.at_nanos());
        }
        assert_eq!(decoded.seed(), schedule.seed());
        assert_eq!(decoded.config_hash(), schedule.config_hash());
        assert_eq!(decoded.terminal_steps(), schedule.terminal_steps());
        assert_eq!(decoded.terminal_nanos(), schedule.terminal_nanos());
        assert_eq!(
            decoded.terminal_schedule_hash(),
            schedule.terminal_schedule_hash()
        );
        assert!(decoded.terminal_quiescent());
        assert!(!decoded.truncated());

        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&replay_observations));
        let replay_report = replay
            .run_forced_schedule(&decoded, ForcedScheduleLimits::new(32, 128))
            .expect("decoded schedule replays exactly");
        assert_eq!(replay_report.dispatches, 6);
        assert_eq!(replay_report.steps, decoded.terminal_steps());
        assert_eq!(
            replay_report.schedule_hash,
            decoded.terminal_schedule_hash()
        );
        assert_eq!(*replay_observations.lock(), *source_observations.lock());

        let candidate_limits = ForcedScheduleCandidateLimits::new(32, 32, 128);
        let all_indices = (0..decoded.dispatches().len()).collect::<Vec<_>>();
        let candidate = decoded
            .derive_candidate(&all_indices, candidate_limits)
            .expect("derive candidate from decoded authority");
        assert_eq!(candidate.source_version(), decoded.version());
        assert_eq!(candidate.seed(), decoded.seed());
        assert_eq!(candidate.config_hash(), decoded.config_hash());
        assert_eq!(
            candidate.source_dispatch_count(),
            decoded.dispatches().len()
        );
        assert_eq!(
            candidate.source_terminal_schedule_hash(),
            decoded.terminal_schedule_hash()
        );
        for (index, (retained, source_dispatch)) in candidate
            .dispatches()
            .iter()
            .zip(decoded.dispatches())
            .enumerate()
        {
            assert_eq!(retained.source_index(), index);
            assert_eq!(retained.task(), source_dispatch.task());
            assert_eq!(retained.worker(), source_dispatch.worker());
            assert_eq!(retained.lane(), source_dispatch.lane());
            assert_eq!(retained.source_step(), source_dispatch.at_step());
            assert_eq!(retained.source_nanos(), source_dispatch.at_nanos());
        }
        let candidate_observations = Arc::new(Mutex::new(Vec::new()));
        let mut candidate_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&candidate_observations));
        let candidate_report = candidate_replay
            .run_forced_schedule_candidate(&candidate, candidate_limits)
            .expect("decoded candidate executes exact retained choices");
        assert_eq!(
            candidate_report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(candidate_report.consumed_source_indices, all_indices);
        assert_eq!(*candidate_observations.lock(), *source_observations.lock());

        for prefix_len in 0..canonical.len() {
            assert!(matches!(
                ForcedSchedule::try_from_canonical_bytes(&canonical[..prefix_len], decode_limits),
                Err(ForcedScheduleArtifactError::Truncated { .. })
            ));
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &trailing,
                ForcedScheduleDecodeLimits::new(trailing.len(), 32, decoded_dispatch_bytes)
            ),
            Err(ForcedScheduleArtifactError::TrailingBytes { .. })
        ));

        for byte_index in 0..canonical.len() {
            let mut corrupted = canonical.clone();
            corrupted[byte_index] ^= 0x80;
            assert!(
                ForcedSchedule::try_from_canonical_bytes(&corrupted, decode_limits).is_err(),
                "byte mutation {byte_index} was accepted"
            );
        }

        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &canonical,
                ForcedScheduleDecodeLimits::new(canonical.len() - 1, 32, decoded_dispatch_bytes)
            ),
            Err(ForcedScheduleArtifactError::ByteLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &canonical,
                ForcedScheduleDecodeLimits::new(
                    canonical.len(),
                    schedule.dispatches().len() - 1,
                    decoded_dispatch_bytes
                )
            ),
            Err(ForcedScheduleArtifactError::DispatchLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &canonical,
                ForcedScheduleDecodeLimits::new(canonical.len(), 32, decoded_dispatch_bytes - 1)
            ),
            Err(ForcedScheduleArtifactError::DecodedAllocationLimitExceeded { .. })
        ));
        let mut impossible_count = canonical[..FORCED_SCHEDULE_ARTIFACT_HEADER_LEN].to_vec();
        write_u64(
            &mut impossible_count,
            FORCED_SCHEDULE_ARTIFACT_COUNT_OFFSET,
            u64::MAX,
        );
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &impossible_count,
                ForcedScheduleDecodeLimits::new(impossible_count.len(), usize::MAX, usize::MAX)
            ),
            Err(ForcedScheduleArtifactError::LengthOverflow { .. })
        ));

        let dispatch0 = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN;
        let dispatch1 = dispatch0 + FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;
        let terminal = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
            + schedule.dispatches().len() * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        rewrite_checksum(&mut wrong_magic);
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&wrong_magic, decode_limits),
            Err(ForcedScheduleArtifactError::MagicMismatch)
        );
        let mut wrong_artifact_version = canonical.clone();
        write_u32(
            &mut wrong_artifact_version,
            8,
            FORCED_SCHEDULE_ARTIFACT_VERSION + 1,
        );
        rewrite_checksum(&mut wrong_artifact_version);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&wrong_artifact_version, decode_limits),
            Err(ForcedScheduleArtifactError::VersionMismatch { .. })
        ));
        let mut wrong_schema = canonical.clone();
        write_u32(&mut wrong_schema, 12, FORCED_SCHEDULE_SCHEMA_VERSION + 1);
        rewrite_checksum(&mut wrong_schema);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&wrong_schema, decode_limits),
            Err(ForcedScheduleArtifactError::SchemaMismatch { .. })
        ));
        let mut unknown_lane = canonical.clone();
        unknown_lane[dispatch0 + 12] = 0xff;
        rewrite_checksum(&mut unknown_lane);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&unknown_lane, decode_limits),
            Err(ForcedScheduleArtifactError::LaneTag {
                index: 0,
                tag: 0xff
            })
        ));
        let mut duplicate_step = canonical.clone();
        write_u64(
            &mut duplicate_step,
            dispatch1 + 13,
            schedule.dispatches()[0].at_step(),
        );
        rewrite_checksum(&mut duplicate_step);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&duplicate_step, decode_limits),
            Err(ForcedScheduleArtifactError::Schedule(
                ForcedScheduleError::StepOrder { index: 1, .. }
            ))
        ));
        let mut backwards_time = canonical.clone();
        write_u64(&mut backwards_time, dispatch0 + 21, 1);
        write_u64(&mut backwards_time, dispatch1 + 21, 0);
        rewrite_checksum(&mut backwards_time);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&backwards_time, decode_limits),
            Err(ForcedScheduleArtifactError::Schedule(
                ForcedScheduleError::TimeOrder { index: 1, .. }
            ))
        ));
        for (offset, field) in [
            (terminal + 24, "terminal_quiescent"),
            (terminal + 25, "truncated"),
        ] {
            let mut invalid_bool = canonical.clone();
            invalid_bool[offset] = 2;
            rewrite_checksum(&mut invalid_bool);
            assert_eq!(
                ForcedSchedule::try_from_canonical_bytes(&invalid_bool, decode_limits),
                Err(ForcedScheduleArtifactError::BooleanTag { field, tag: 2 })
            );
        }
        for (offset, value) in [(terminal + 24, 0), (terminal + 25, 1)] {
            let mut partial = canonical.clone();
            partial[offset] = value;
            rewrite_checksum(&mut partial);
            assert_eq!(
                ForcedSchedule::try_from_canonical_bytes(&partial, decode_limits),
                Err(ForcedScheduleArtifactError::Schedule(
                    ForcedScheduleError::PartialSource
                ))
            );
        }
        let mut impossible_terminal = canonical.clone();
        write_u64(
            &mut impossible_terminal,
            terminal,
            schedule
                .dispatches()
                .last()
                .expect("last dispatch")
                .at_step()
                - 1,
        );
        rewrite_checksum(&mut impossible_terminal);
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&impossible_terminal, decode_limits),
            Err(ForcedScheduleArtifactError::Schedule(
                ForcedScheduleError::PartialSource
            ))
        );

        let mut wrong_seed = canonical.clone();
        write_u64(&mut wrong_seed, 16, schedule.seed() ^ 1);
        rewrite_checksum(&mut wrong_seed);
        let wrong_seed = ForcedSchedule::try_from_canonical_bytes(&wrong_seed, decode_limits)
            .expect("authenticated alternate seed decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_seed, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::SeedMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_config = canonical.clone();
        write_u64(&mut wrong_config, 24, schedule.config_hash() ^ 1);
        rewrite_checksum(&mut wrong_config);
        let wrong_config = ForcedSchedule::try_from_canonical_bytes(&wrong_config, decode_limits)
            .expect("authenticated alternate config decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_config, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::ConfigMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_task = canonical.clone();
        write_u64(
            &mut wrong_task,
            dispatch0,
            schedule.dispatches()[0].task().0 ^ 1,
        );
        rewrite_checksum(&mut wrong_task);
        let wrong_task = ForcedSchedule::try_from_canonical_bytes(&wrong_task, decode_limits)
            .expect("authenticated alternate task decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_task, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::TaskUnavailable { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_worker = canonical.clone();
        write_u32(&mut wrong_worker, dispatch0 + 8, u32::MAX);
        rewrite_checksum(&mut wrong_worker);
        let wrong_worker = ForcedSchedule::try_from_canonical_bytes(&wrong_worker, decode_limits)
            .expect("authenticated alternate worker decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_worker, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::WorkerUnavailable { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_lane = canonical.clone();
        wrong_lane[dispatch0 + 12] = match schedule.dispatches()[0].lane() {
            DispatchLane::Cancel => forced_schedule_lane_tag(DispatchLane::Ready),
            DispatchLane::Timed | DispatchLane::Ready | DispatchLane::Stolen => {
                forced_schedule_lane_tag(DispatchLane::Cancel)
            }
        };
        rewrite_checksum(&mut wrong_lane);
        let wrong_lane = ForcedSchedule::try_from_canonical_bytes(&wrong_lane, decode_limits)
            .expect("authenticated alternate lane decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_lane, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_terminal_hash = canonical.clone();
        write_u64(
            &mut wrong_terminal_hash,
            terminal + 16,
            schedule.terminal_schedule_hash() ^ 1,
        );
        rewrite_checksum(&mut wrong_terminal_hash);
        let wrong_terminal_hash =
            ForcedSchedule::try_from_canonical_bytes(&wrong_terminal_hash, decode_limits)
                .expect("authenticated alternate terminal hash decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config, Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_terminal_hash, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::CertificateMismatch { .. })
        ));
        assert_eq!(observations.lock().len(), 6);

        crate::test_complete!("forced_schedule_artifact_codec_is_canonical_bounded_and_replayable");
    }

    fn pending_spawn_with_future_reactor_fixture(
        config: LabConfig,
        observations: Arc<Mutex<Vec<u64>>>,
    ) -> LabRuntime {
        let mut runtime = LabRuntime::new(config);
        let token = Token::new(0xCAAD);
        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_secs(1));

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let pending = runtime
            .state
            .region(root)
            .expect("root region")
            .pending_spawn_handle();
        let parent: crate::cx::Cx = crate::cx::Cx::new_with_drivers(
            root,
            TaskId::from_arena(ArenaIndex::new(u32::MAX - 1, 0)),
            Budget::INFINITE,
            None,
            runtime.state.io_driver_handle(),
            None,
            runtime.state.timer_driver_handle(),
            None,
        )
        .with_spawn_gateway(runtime.state.spawn_gateway())
        .with_pending_spawn_counter(Some(pending));
        let _handle = parent
            .spawn(|child| async move {
                observations.lock().push(child.now().as_nanos());
            })
            .expect("managed spawn enqueues");
        assert_eq!(runtime.spawn_mailbox.len(), 1);
        runtime
    }

    fn pending_command_before_timer_fixture(
        config: LabConfig,
        observations: Arc<Mutex<Vec<u64>>>,
    ) -> LabRuntime {
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let gateway = runtime.state.spawn_gateway().expect("lab spawn gateway");
        let missing = TaskId::from_arena(ArenaIndex::new(u32::MAX - 2, 0));
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                observations.lock().push(now.as_nanos());
                assert!(gateway.enqueue_handle_cancel(missing, CancelReason::shutdown()));
                crate::time::sleep(now, Duration::from_secs(1)).await;
                let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                observations.lock().push(now.as_nanos());
            })
            .expect("create command-before-timer task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime
    }

    #[test]
    fn pending_dispatch_auto_advance_before_future_deadline() {
        init_test("pending_dispatch_auto_advance_before_future_deadline");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = pending_spawn_with_future_reactor_fixture(
            LabConfig::new(0xCAAD_A070).max_steps(32),
            Arc::clone(&observations),
        );

        let report = runtime.run_with_auto_advance();

        assert_eq!(
            *observations.lock(),
            vec![0],
            "queued spawn work must run before an unrelated future reactor deadline"
        );
        assert_eq!(report.termination, AutoAdvanceTermination::Quiescent);
        assert_eq!(runtime.now(), Time::from_secs(1));
        crate::test_complete!("pending_dispatch_auto_advance_before_future_deadline");
    }

    #[test]
    fn the_auto_advance_flag_moves_time_for_run_until_quiescent() {
        init_test("the_auto_advance_flag_moves_time_for_run_until_quiescent");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = pending_command_before_timer_fixture(
            LabConfig::new(0xA070_0001)
                .with_auto_advance()
                .max_steps(64),
            Arc::clone(&observations),
        );
        runtime.run_until_quiescent();
        assert!(runtime.is_quiescent(), "the sleeping task finished");
        assert_eq!(*observations.lock(), vec![0, 1_000_000_000]);
        assert_eq!(runtime.now(), Time::from_secs(1));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = pending_command_before_timer_fixture(
            LabConfig::new(0xA070_0001).max_steps(64),
            Arc::clone(&observations),
        );
        runtime.run_until_quiescent();
        assert!(!runtime.is_quiescent(), "without the flag time stays put");
        assert_eq!(*observations.lock(), vec![0]);
        assert_eq!(runtime.now(), Time::ZERO);

        let (woke_at, report) = run_async_under_lab_with_config(
            LabConfig::new(0xA070_0002).with_auto_advance(),
            |cx| async move {
                crate::time::sleep(cx.now(), Duration::from_millis(1)).await;
                cx.now()
            },
        );
        assert!(report.quiescent);
        assert_eq!(woke_at, Time::from_millis(1));
        crate::test_complete!("the_auto_advance_flag_moves_time_for_run_until_quiescent");
    }

    #[test]
    fn auto_advance_under_a_paused_clock_bails_out_instead_of_spinning() {
        init_test("auto_advance_under_a_paused_clock_bails_out_instead_of_spinning");
        let (done, outcome) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut runtime = pending_command_before_timer_fixture(
                LabConfig::new(0xA070_0003).max_steps(1_000_000),
                Arc::new(Mutex::new(Vec::new())),
            );
            runtime.pause_clock();
            let _ = done.send(runtime.run_with_auto_advance().termination);
        });
        let termination = outcome
            .recv_timeout(Duration::from_secs(30))
            .expect("run_with_auto_advance returns while the clock is paused");
        assert_eq!(termination, AutoAdvanceTermination::StuckBailout);
        crate::test_complete!("auto_advance_under_a_paused_clock_bails_out_instead_of_spinning");
    }

    #[test]
    fn pending_dispatch_run_until_idle_admits_spawn() {
        init_test("pending_dispatch_run_until_idle_admits_spawn");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = pending_spawn_with_future_reactor_fixture(
            LabConfig::new(0x1D1E_CAAD).max_steps(32),
            Arc::clone(&observations),
        );

        assert_eq!(runtime.run_until_idle(), 1);
        assert_eq!(
            *observations.lock(),
            vec![0],
            "idle detection must admit and poll queued managed spawns"
        );
        assert!(runtime.spawn_mailbox.is_empty());
        crate::test_complete!("pending_dispatch_run_until_idle_admits_spawn");
    }

    #[test]
    fn pending_dispatch_forced_candidate_before_future_deadline() {
        init_test("pending_dispatch_forced_candidate_before_future_deadline");
        let config = LabConfig::new(0xCAAD_CAAD).max_steps(32);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = pending_spawn_with_future_reactor_fixture(
            config.clone(),
            Arc::clone(&source_observations),
        );
        source
            .start_forced_schedule_recording(4)
            .expect("start exact dispatch capture");
        source.step();
        assert!(source.is_quiescent());
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("capture one pending-spawn dispatch");
        assert_eq!(schedule.dispatches().len(), 1);
        assert_eq!(schedule.dispatches()[0].at_nanos(), 0);
        assert_eq!(*source_observations.lock(), vec![0]);

        let limits = ForcedScheduleCandidateLimits::new(4, 4, 16);
        let candidate = schedule
            .derive_candidate(&[0], limits)
            .expect("derive full-retention candidate");
        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay =
            pending_spawn_with_future_reactor_fixture(config, Arc::clone(&replay_observations));
        let report = replay
            .run_forced_schedule_candidate(&candidate, limits)
            .expect("candidate must drain spawn admission before time advancement");

        assert_eq!(
            report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(report.consumed_source_indices, vec![0]);
        assert_eq!(*replay_observations.lock(), vec![0]);
        assert_eq!(report.lab.now_nanos, 0);
        crate::test_complete!("pending_dispatch_forced_candidate_before_future_deadline");
    }

    #[test]
    fn pending_dispatch_forced_candidate_before_later_retained_dispatch() {
        init_test("pending_dispatch_forced_candidate_before_later_retained_dispatch");
        let config = LabConfig::new(0xCAAD_C0DE).max_steps(32);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source =
            pending_command_before_timer_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(4)
            .expect("start exact dispatch capture");
        let source_report = source.run_with_auto_advance();
        assert_eq!(source_report.termination, AutoAdvanceTermination::Quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("capture both task dispatches");
        assert_eq!(schedule.dispatches().len(), 2);
        assert_eq!(*source_observations.lock(), vec![0, 1_000_000_000]);

        let limits = ForcedScheduleCandidateLimits::new(4, 4, 16);
        let candidate = schedule
            .derive_candidate(&[0, 1], limits)
            .expect("derive full-retention candidate");
        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay =
            pending_command_before_timer_fixture(config, Arc::clone(&replay_observations));
        let report = replay
            .run_forced_schedule_candidate(&candidate, limits)
            .expect("candidate must pump the command before advancing to the retained wake");

        assert_eq!(
            report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(report.consumed_source_indices, vec![0, 1]);
        assert_eq!(*replay_observations.lock(), vec![0, 1_000_000_000]);
        assert_eq!(report.lab.now_nanos, 1_000_000_000);
        crate::test_complete!("pending_dispatch_forced_candidate_before_later_retained_dispatch");
    }

    #[test]
    fn forced_schedule_replay_executes_recorded_choices_before_polling() {
        init_test("forced_schedule_replay_executes_recorded_choices_before_polling");
        let config = LabConfig::new(0xF0CE_D5CE).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        let source_report = source.run_until_quiescent_with_report();
        assert!(source_report.quiescent, "source fixture must quiesce");
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");
        assert_eq!(schedule.version(), FORCED_SCHEDULE_SCHEMA_VERSION);
        assert_eq!(schedule.seed(), config.seed);
        assert_eq!(schedule.dispatches().len(), 6);
        assert_eq!(
            schedule.terminal_schedule_hash(),
            source_report.trace_certificate.schedule_hash
        );

        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, Arc::clone(&replay_observations));
        let receipt = replay
            .run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 128))
            .expect("recorded dispatch projection must execute exactly");

        assert!(receipt.quiescent);
        assert_eq!(receipt.dispatches, schedule.dispatches().len());
        assert_eq!(receipt.steps, schedule.terminal_steps());
        assert_eq!(receipt.terminal_nanos, schedule.terminal_nanos());
        assert_eq!(receipt.schedule_hash, schedule.terminal_schedule_hash());
        assert_eq!(*replay_observations.lock(), *source_observations.lock());
        crate::test_complete!("forced_schedule_replay_executes_recorded_choices_before_polling");
    }

    fn recorded_forced_schedule_fixture() -> ForcedSchedule {
        let config = LabConfig::new(0xA471_FAC7).worker_count(2).max_steps(128);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config, observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start artifact fixture capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        source
            .finish_forced_schedule_recording()
            .expect("finish complete artifact fixture capture")
    }

    fn reseal_forced_schedule_artifact(bytes: &mut [u8]) {
        let checksum_offset = bytes.len() - FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN;
        let checksum = forced_schedule_artifact_checksum(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
    }

    #[test]
    fn forced_schedule_artifact_roundtrip_is_exact_and_bounded() {
        init_test("forced_schedule_artifact_roundtrip_is_exact_and_bounded");
        let schedule = recorded_forced_schedule_fixture();
        let bytes = schedule
            .to_canonical_bytes()
            .expect("encode complete forced schedule");
        assert_eq!(
            schedule.to_canonical_bytes().expect("repeat encoding"),
            bytes,
            "canonical encoding must be deterministic"
        );

        let decoded_bytes = std::mem::size_of_val(schedule.dispatches());
        let limits = ForcedScheduleDecodeLimits::new(
            bytes.len(),
            schedule.dispatches().len(),
            decoded_bytes,
        );
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&bytes, limits)
                .expect("decode canonical artifact"),
            schedule
        );

        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &bytes,
                ForcedScheduleDecodeLimits::new(
                    bytes.len() - 1,
                    schedule.dispatches().len(),
                    decoded_bytes,
                ),
            ),
            Err(ForcedScheduleArtifactError::ByteLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &bytes,
                ForcedScheduleDecodeLimits::new(
                    bytes.len(),
                    schedule.dispatches().len() - 1,
                    decoded_bytes,
                ),
            ),
            Err(ForcedScheduleArtifactError::DispatchLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &bytes,
                ForcedScheduleDecodeLimits::new(
                    bytes.len(),
                    schedule.dispatches().len(),
                    decoded_bytes - 1,
                ),
            ),
            Err(ForcedScheduleArtifactError::DecodedAllocationLimitExceeded { .. })
        ));
        crate::test_complete!("forced_schedule_artifact_roundtrip_is_exact_and_bounded");
    }

    #[test]
    fn forced_schedule_artifact_rejects_hostile_encodings() {
        init_test("forced_schedule_artifact_rejects_hostile_encodings");
        let schedule = recorded_forced_schedule_fixture();
        let bytes = schedule
            .to_canonical_bytes()
            .expect("encode complete forced schedule");
        let limits = ForcedScheduleDecodeLimits::new(
            bytes.len() + 1,
            schedule.dispatches().len() + 1,
            (schedule.dispatches().len() + 1) * std::mem::size_of::<ForcedDispatch>(),
        );

        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&bytes[..12], limits),
            Err(ForcedScheduleArtifactError::Truncated { .. })
        ));

        let mut malformed = bytes.clone();
        malformed[0] ^= 0x80;
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::MagicMismatch)
        );

        let mut malformed = bytes.clone();
        malformed[8..12].copy_from_slice(&(FORCED_SCHEDULE_ARTIFACT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::VersionMismatch { .. })
        ));

        let mut malformed = bytes.clone();
        malformed.push(0);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::TrailingBytes { .. })
        ));

        let mut malformed = bytes.clone();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::ChecksumMismatch)
        );

        let mut malformed = bytes.clone();
        malformed[FORCED_SCHEDULE_ARTIFACT_HEADER_LEN + 12] = u8::MAX;
        reseal_forced_schedule_artifact(&mut malformed);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::LaneTag { index: 0, .. })
        ));

        let mut malformed = bytes;
        let terminal_offset = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
            + schedule.dispatches().len() * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;
        malformed[terminal_offset + 24] = 2;
        reseal_forced_schedule_artifact(&mut malformed);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::BooleanTag {
                field: "terminal_quiescent",
                tag: 2,
            })
        ));
        crate::test_complete!("forced_schedule_artifact_rejects_hostile_encodings");
    }

    #[test]
    fn forced_schedule_artifact_refuses_partial_authority() {
        init_test("forced_schedule_artifact_refuses_partial_authority");
        let config = LabConfig::new(0xA471_0BAD).max_steps(128);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config, observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start partial artifact fixture capture");
        let partial = source
            .finish_forced_schedule_recording()
            .expect("finish represented partial capture");

        assert_eq!(
            partial.to_canonical_bytes(),
            Err(ForcedScheduleArtifactError::Schedule(
                ForcedScheduleError::PartialSource
            ))
        );
        crate::test_complete!("forced_schedule_artifact_refuses_partial_authority");
    }

    #[test]
    fn forced_schedule_candidate_executes_only_retained_source_choices() {
        init_test("forced_schedule_candidate_executes_only_retained_source_choices");
        let config = LabConfig::new(0xCAAD_1DA7).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        let source_report = source.run_until_quiescent_with_report();
        assert!(source_report.quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");
        let limits = ForcedScheduleCandidateLimits::new(32, 32, 128);
        let all_indices = (0..schedule.dispatches().len()).collect::<Vec<_>>();
        let full = schedule
            .derive_candidate(&all_indices, limits)
            .expect("derive full-retention candidate");
        assert_eq!(full.version(), FORCED_SCHEDULE_CANDIDATE_SCHEMA_VERSION);
        assert_eq!(full.source_version(), FORCED_SCHEDULE_SCHEMA_VERSION);
        assert_eq!(full.seed(), schedule.seed());
        assert_eq!(full.config_hash(), schedule.config_hash());
        assert_eq!(
            full.source_terminal_schedule_hash(),
            schedule.terminal_schedule_hash()
        );
        assert_eq!(full.source_dispatch_count(), schedule.dispatches().len());
        assert_eq!(
            full.dispatches()
                .iter()
                .map(ForcedScheduleCandidateDispatch::source_index)
                .collect::<Vec<_>>(),
            all_indices
        );

        let exact_observations = Arc::new(Mutex::new(Vec::new()));
        let mut exact_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&exact_observations));
        let exact_report = exact_replay
            .run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 128))
            .expect("complete source schedule must still replay exactly");

        let full_observations = Arc::new(Mutex::new(Vec::new()));
        let mut full_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&full_observations));
        let full_report = full_replay
            .run_forced_schedule_candidate(&full, limits)
            .expect("full candidate must execute without RNG fallback");
        assert_eq!(
            full_report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(full_report.consumed_source_indices, all_indices);
        assert!(full_report.lab.quiescent);
        assert_eq!(full_report.lab.steps_total, schedule.terminal_steps());
        assert_eq!(full_report.lab.now_nanos, schedule.terminal_nanos());
        assert_eq!(
            full_report.lab.trace_certificate.schedule_hash,
            schedule.terminal_schedule_hash()
        );
        assert_eq!(full_report.lab.steps_total, exact_report.steps);
        assert_eq!(full_report.lab.now_nanos, exact_report.terminal_nanos);
        assert_eq!(
            full_report.lab.trace_certificate.schedule_hash,
            exact_report.schedule_hash
        );
        assert_eq!(full_report.lab.quiescent, exact_report.quiescent);
        assert_eq!(*full_observations.lock(), *source_observations.lock());
        assert_eq!(*full_observations.lock(), *exact_observations.lock());

        let retained = schedule
            .derive_candidate(&[1], limits)
            .expect("derive one-choice candidate");
        assert_eq!(retained.dispatches()[0].source_index(), 1);
        assert_eq!(
            retained.dispatches()[0].task(),
            schedule.dispatches()[1].task()
        );
        assert_eq!(
            retained.dispatches()[0].worker(),
            schedule.dispatches()[1].worker()
        );
        assert_eq!(
            retained.dispatches()[0].lane(),
            schedule.dispatches()[1].lane()
        );
        assert_eq!(
            retained.dispatches()[0].source_step(),
            schedule.dispatches()[1].at_step()
        );
        assert_eq!(
            retained.dispatches()[0].source_nanos(),
            schedule.dispatches()[1].at_nanos()
        );
        let retained_observations = Arc::new(Mutex::new(Vec::new()));
        let mut retained_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&retained_observations));
        let retained_report = retained_replay
            .run_forced_schedule_candidate(&retained, limits)
            .expect("retained source choice must execute directly");
        assert_eq!(
            retained_report.termination,
            ForcedScheduleCandidateTermination::Exhausted
        );
        assert_eq!(retained_report.consumed_source_indices, vec![1]);
        assert_eq!(retained_observations.lock().len(), 1);
        assert!(!retained_report.lab.quiescent);

        let empty = schedule
            .derive_candidate(&[], limits)
            .expect("derive empty deletion candidate");
        let empty_observations = Arc::new(Mutex::new(Vec::new()));
        let mut empty_replay = forced_schedule_fixture(config, Arc::clone(&empty_observations));
        let empty_report = empty_replay
            .run_forced_schedule_candidate(&empty, limits)
            .expect("empty candidate must report exhaustion without RNG polling");
        assert_eq!(
            empty_report.termination,
            ForcedScheduleCandidateTermination::Exhausted
        );
        assert!(empty_report.consumed_source_indices.is_empty());
        assert_eq!(empty_report.work_units, 0);
        assert!(empty_observations.lock().is_empty());
        crate::test_complete!("forced_schedule_candidate_executes_only_retained_source_choices");
    }

    #[test]
    fn forced_schedule_candidate_admission_is_bounded_and_source_derived() {
        init_test("forced_schedule_candidate_admission_is_bounded_and_source_derived");
        let config = LabConfig::new(0xCAAD_B0AD).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), source_observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");
        let source_len = schedule.dispatches().len();
        let limits = ForcedScheduleCandidateLimits::new(32, 32, 128);

        assert!(matches!(
            schedule.derive_candidate(&[], ForcedScheduleCandidateLimits::new(0, 32, 128)),
            Err(ForcedScheduleError::ZeroCandidateLimit {
                limit_name: "max_source_dispatches"
            })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[], ForcedScheduleCandidateLimits::new(32, 0, 128)),
            Err(ForcedScheduleError::ZeroCandidateLimit {
                limit_name: "max_candidate_dispatches"
            })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[], ForcedScheduleCandidateLimits::new(32, 32, 0)),
            Err(ForcedScheduleError::ZeroCandidateLimit {
                limit_name: "max_work_units"
            })
        ));
        assert!(matches!(
            schedule.derive_candidate(
                &[],
                ForcedScheduleCandidateLimits::new(source_len - 1, 32, 128)
            ),
            Err(ForcedScheduleError::CandidateSourceLimitExceeded { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[0, 1], ForcedScheduleCandidateLimits::new(32, 1, 128)),
            Err(ForcedScheduleError::DispatchLimitExceeded { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[0, 0], limits),
            Err(ForcedScheduleError::CandidateIndexOrder { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[1, 0], limits),
            Err(ForcedScheduleError::CandidateIndexOrder { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[source_len], limits),
            Err(ForcedScheduleError::CandidateIndexOutOfRange { .. })
        ));

        let all_indices = (0..source_len).collect::<Vec<_>>();
        let full = schedule
            .derive_candidate(&all_indices, limits)
            .expect("derive valid full candidate");
        let work_limited_observations = Arc::new(Mutex::new(Vec::new()));
        let mut work_limited =
            forced_schedule_fixture(config.clone(), Arc::clone(&work_limited_observations));
        assert!(matches!(
            work_limited.run_forced_schedule_candidate(
                &full,
                ForcedScheduleCandidateLimits::new(32, 32, 1)
            ),
            Err(ForcedScheduleError::CandidateWorkLimitExceeded { .. })
        ));
        assert!(
            work_limited_observations.lock().is_empty(),
            "minimum work refusal polled a task"
        );

        let mut wrong_task = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_task.dispatches[0].dispatch.task.0 ^= 1;
        let wrong_task_observations = Arc::new(Mutex::new(Vec::new()));
        let mut wrong_task_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&wrong_task_observations));
        assert!(matches!(
            wrong_task_replay.run_forced_schedule_candidate(&wrong_task, limits),
            Err(ForcedScheduleError::TaskUnavailable { index: 0, .. })
        ));
        assert!(wrong_task_observations.lock().is_empty());

        let mut wrong_config = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_config.config_hash ^= 1;
        let wrong_config_observations = Arc::new(Mutex::new(Vec::new()));
        let mut wrong_config_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&wrong_config_observations));
        assert!(matches!(
            wrong_config_replay.run_forced_schedule_candidate(&wrong_config, limits),
            Err(ForcedScheduleError::ConfigMismatch { .. })
        ));
        assert!(wrong_config_observations.lock().is_empty());

        let mut wrong_candidate_version = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_candidate_version.version += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_candidate_version, limits),
            Err(ForcedScheduleError::CandidateSchemaMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_source_version = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_source_version.source_version += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_source_version, limits),
            Err(ForcedScheduleError::SchemaMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_seed = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_seed.seed ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_seed, limits),
            Err(ForcedScheduleError::SeedMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_order = schedule
            .derive_candidate(&[0, 1], limits)
            .expect("derive source-owned candidate");
        wrong_order.dispatches.swap(0, 1);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_order, limits),
            Err(ForcedScheduleError::CandidateIndexOrder { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_worker = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_worker.dispatches[0].dispatch.worker ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_worker, limits),
            Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
                | Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_lane = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_lane.dispatches[0].dispatch.lane = match wrong_lane.dispatches[0].dispatch.lane {
            DispatchLane::Cancel => DispatchLane::Ready,
            DispatchLane::Timed | DispatchLane::Ready | DispatchLane::Stolen => {
                DispatchLane::Cancel
            }
        };
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_lane, limits),
            Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
                | Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());
        crate::test_complete!("forced_schedule_candidate_admission_is_bounded_and_source_derived");
    }

    #[test]
    fn forced_schedule_mutations_refuse_before_the_wrong_poll() {
        init_test("forced_schedule_mutations_refuse_before_the_wrong_poll");
        let config = LabConfig::new(0xF0CE_D5CE).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), source_observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");

        let mut wrong_tick = schedule.clone();
        for dispatch in &mut wrong_tick.dispatches {
            dispatch.at_step += 1;
        }
        wrong_tick.terminal_steps += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_tick, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::EarlyRunnable { .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "tick mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "tick refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_time = schedule.clone();
        for dispatch in &mut wrong_time.dispatches {
            dispatch.at_nanos += 1;
        }
        wrong_time.terminal_nanos += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_time, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::TimeMismatch { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "time mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "time refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_task = schedule.clone();
        wrong_task.dispatches[0].task.0 ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_task, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::TaskUnavailable { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "generation mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "task refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_worker = schedule.clone();
        wrong_worker.dispatches[0].worker ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_worker, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
                | Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "worker mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "worker refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_lane = schedule.clone();
        wrong_lane.dispatches[0].lane = match wrong_lane.dispatches[0].lane {
            DispatchLane::Cancel => DispatchLane::Ready,
            DispatchLane::Timed | DispatchLane::Ready | DispatchLane::Stolen => {
                DispatchLane::Cancel
            }
        };
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_lane, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
                | Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "lane mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "lane refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_order = schedule.clone();
        wrong_order.dispatches.swap(0, 1);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_order, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::StepOrder { .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "order mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "order refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);
        crate::test_complete!("forced_schedule_mutations_refuse_before_the_wrong_poll");
    }

    #[test]
    fn forced_schedule_partial_and_resource_limited_receipts_fail_closed() {
        init_test("forced_schedule_partial_and_resource_limited_receipts_fail_closed");
        let config = LabConfig::new(0xF0CE_D5CE).max_steps(128);

        let mut source = LabRuntime::new(config.clone());
        source
            .start_forced_schedule_recording(1)
            .expect("start empty terminal-time capture");
        source.advance_time_to(Time::from_nanos(17));
        let terminal_time_only = source
            .finish_forced_schedule_recording()
            .expect("finish empty terminal-time capture");
        assert!(terminal_time_only.dispatches().is_empty());
        let mut replay = LabRuntime::new(config.clone());
        assert!(matches!(
            replay.run_forced_schedule(&terminal_time_only, ForcedScheduleLimits::new(1, 1)),
            Err(ForcedScheduleError::TerminalMismatch {
                expected_nanos: 17,
                actual_nanos: 0,
                ..
            })
        ));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start deliberately partial capture");
        let partial = source
            .finish_forced_schedule_recording()
            .expect("partial source is represented, not silently promoted");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert_eq!(
            replay.run_forced_schedule(&partial, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::PartialSource)
        );
        assert!(observations.lock().is_empty());

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), observations);
        source
            .start_forced_schedule_recording(1)
            .expect("start deliberately bounded capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        assert!(matches!(
            source.finish_forced_schedule_recording(),
            Err(ForcedScheduleError::RecordingLimitExceeded { max_dispatches: 1 })
        ));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), observations);
        assert!(matches!(
            replay.run_forced_schedule(&schedule, ForcedScheduleLimits::new(1, 128)),
            Err(ForcedScheduleError::DispatchLimitExceeded { .. })
        ));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 1)),
            Err(ForcedScheduleError::WorkLimitExceeded { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut mismatched_config = config.clone();
        mismatched_config.enable_cancellation_oracle = !config.enable_cancellation_oracle;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(mismatched_config, Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::ConfigMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut truncated = schedule.clone();
        truncated.dispatches.pop();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, observations);
        assert!(matches!(
            replay.run_forced_schedule(&truncated, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::ScheduleExhausted { .. })
                | Err(ForcedScheduleError::CertificateMismatch { .. })
        ));
        crate::test_complete!("forced_schedule_partial_and_resource_limited_receipts_fail_closed");
    }

    /// Regression test: replay recorder must capture the actual completion
    /// severity from the finalized task record, not always `Severity::Ok`.
    ///
    /// `create_task` wraps futures to always return `Outcome::Ok(())` — the
    /// real severity is determined by the cancel protocol state machine. This
    /// test puts a task through the cancel protocol and verifies the replay
    /// trace records the correct `Cancelled` severity.
    #[test]
    fn replay_records_correct_severity_for_cancelled_task() {
        init_test("replay_records_correct_severity_for_cancelled_task");

        let config = LabConfig::new(42)
            .panic_on_leak(false)
            .with_default_replay_recording();
        let mut runtime = LabRuntime::new(config);
        let root = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);

        // Create a task that yields once then completes with Ok.
        // The yield allows us to cancel the task before it finishes.
        let (task_id, _) = runtime
            .state
            .create_task(root, crate::types::Budget::INFINITE, async {
                crate::runtime::yield_now::yield_now().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        // Step once: task yields (Pending)
        runtime.step();

        // Put the task through cancel protocol: CancelRequested → Cancelling
        let cancel_effects = runtime
            .state
            .update_task(task_id, |record| {
                let effects =
                    record.request_cancel(crate::types::CancelReason::user("test-cancel"));
                let _ = record.acknowledge_cancel();
                // Task is now in Cancelling state
                assert!(
                    matches!(
                        record.state,
                        crate::record::task::TaskState::Cancelling { .. }
                    ),
                    "task should be in Cancelling state"
                );
                effects
            })
            .unwrap();

        // Reschedule and run to completion: the cancel protocol will
        // complete it as Cancelled when the wrapped future returns Ok.
        runtime.scheduler.lock().schedule_cancel(task_id, 0);
        let (_, cancel_wakes) = cancel_effects.into_parts();
        cancel_wakes.dispatch();
        runtime.run_until_quiescent();

        // Verify the task completed as Cancelled
        if let Some(record) = runtime.state.task(task_id) {
            assert!(
                matches!(
                    record.state,
                    crate::record::task::TaskState::Completed(crate::types::Outcome::Cancelled(_))
                ),
                "task should be Completed(Cancelled), got {:?}",
                record.state
            );
        }

        // Check the replay trace for the TaskCompleted event
        let replay = runtime
            .replay_recorder()
            .snapshot()
            .expect("replay recording enabled");
        let completed_events: Vec<_> = replay
            .events
            .iter()
            .filter(|e| matches!(e, crate::trace::replay::ReplayEvent::TaskCompleted { .. }))
            .collect();

        assert!(
            !completed_events.is_empty(),
            "should have at least one TaskCompleted event"
        );

        // The severity should be Cancelled (2), not Ok (0)
        for event in &completed_events {
            if let crate::trace::replay::ReplayEvent::TaskCompleted { outcome, .. } = event {
                let expected = crate::types::Severity::Cancelled.as_u8();
                crate::assert_with_log!(
                    *outcome == expected,
                    "severity should be Cancelled (2)",
                    expected,
                    *outcome
                );
            }
        }

        crate::test_complete!("replay_records_correct_severity_for_cancelled_task");
    }

    #[test]
    fn replay_recording_metadata_is_stable_for_same_seed() {
        init_test("replay_recording_metadata_is_stable_for_same_seed");

        let mut first = LabRuntime::new(LabConfig::new(42).with_default_replay_recording());
        let mut second = LabRuntime::new(LabConfig::new(42).with_default_replay_recording());

        let first_trace = first
            .finish_replay_trace()
            .expect("first replay recording enabled");
        let second_trace = second
            .finish_replay_trace()
            .expect("second replay recording enabled");

        crate::assert_with_log!(
            first_trace.metadata == second_trace.metadata,
            "replay metadata should match for identical seeds",
            &first_trace.metadata,
            &second_trace.metadata
        );
        crate::assert_with_log!(
            first_trace.events == second_trace.events,
            "replay events should match for identical seeds",
            &first_trace.events,
            &second_trace.events
        );
        crate::assert_with_log!(
            first_trace.metadata.recorded_at == 0,
            "recorded_at defaults to deterministic zero stamp",
            0u64,
            first_trace.metadata.recorded_at
        );

        crate::test_complete!("replay_recording_metadata_is_stable_for_same_seed");
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn lab_trace_certificate_summary_debug_clone_copy_eq() {
        let summary = LabTraceCertificateSummary {
            event_hash: 123,
            event_count: 456,
            schedule_hash: 789,
        };
        let copied = summary;
        let cloned = summary;
        assert_eq!(copied, cloned);
        assert_ne!(
            summary,
            LabTraceCertificateSummary {
                event_hash: 0,
                event_count: 456,
                schedule_hash: 789,
            }
        );
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("LabTraceCertificateSummary"));
    }

    #[test]
    fn virtual_time_report_debug_clone_copy_eq() {
        let report = VirtualTimeReport {
            steps: 100,
            auto_advances: 5,
            total_wakeups: 10,
            time_start: Time::ZERO,
            time_end: Time::from_millis(500),
            virtual_elapsed_nanos: 500_000_000,
            termination: AutoAdvanceTermination::Quiescent,
        };
        let copied = report;
        assert_eq!(copied, report);
        assert_eq!(report.virtual_elapsed_ms(), 500);
        assert_eq!(report.virtual_elapsed_secs(), 0);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("VirtualTimeReport"));
    }

    // =========================================================================
    // AutoAdvanceTermination tests (bead 56c785)
    // =========================================================================

    #[asupersync::lab_test(seeds = 42..43)]
    fn auto_advance_quiescent_termination(lab: &mut LabRuntime) {
        // No tasks enqueued → immediately quiescent
        let report = lab.run_with_auto_advance();
        assert_eq!(
            report.termination,
            AutoAdvanceTermination::Quiescent,
            "empty runtime should terminate as quiescent"
        );
    }

    #[test]
    fn auto_advance_step_limit_termination() {
        init_test("auto_advance_step_limit_termination");
        let mut lab = LabRuntime::new(LabConfig::new(42).max_steps(0));
        let report = lab.run_with_auto_advance();
        assert_eq!(
            report.termination,
            AutoAdvanceTermination::StepLimitReached,
            "zero max_steps should terminate as step-limit-reached"
        );
        crate::test_complete!("auto_advance_step_limit_termination");
    }

    #[test]
    fn auto_advance_stuck_bailout_termination() {
        init_test("auto_advance_stuck_bailout_termination");
        let config = LabConfig::new(42)
            .with_auto_advance()
            .no_step_limit()
            .futurelock_max_idle_steps(0);
        let mut lab = LabRuntime::new(config);
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create pending task");
        lab.scheduler.lock().schedule(task_id, 0);

        let report = lab.run_with_auto_advance();
        assert_eq!(
            report.termination,
            AutoAdvanceTermination::StuckBailout,
            "pending task without deadlines should terminate via stuck bailout"
        );
        assert!(
            !lab.is_quiescent(),
            "stuck bailout should preserve non-quiescent state for diagnosis"
        );
        assert_eq!(
            report.auto_advances, 0,
            "stuck bailout path should not auto-advance virtual time without deadlines"
        );
        crate::test_complete!("auto_advance_stuck_bailout_termination");
    }

    #[test]
    fn auto_advance_termination_display() {
        assert_eq!(
            format!("{}", AutoAdvanceTermination::Quiescent),
            "quiescent"
        );
        assert_eq!(
            format!("{}", AutoAdvanceTermination::StepLimitReached),
            "step-limit-reached"
        );
        assert_eq!(
            format!("{}", AutoAdvanceTermination::StuckBailout),
            "stuck-bailout"
        );
    }

    #[test]
    fn auto_advance_termination_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let variants = [
            AutoAdvanceTermination::Quiescent,
            AutoAdvanceTermination::StepLimitReached,
            AutoAdvanceTermination::StuckBailout,
        ];
        // Copy + Clone + Eq
        for &v in &variants {
            let copied = v;
            let cloned = v;
            assert_eq!(copied, cloned);
        }
        // Hash uniqueness
        let mut set = HashSet::new();
        for &v in &variants {
            assert!(set.insert(v));
        }
        assert_eq!(set.len(), 3);
        // Debug contains type name
        let dbg = format!("{:?}", AutoAdvanceTermination::StuckBailout);
        assert!(dbg.contains("StuckBailout"));
    }

    #[test]
    fn harness_attachment_kind_debug_clone_copy_eq_hash_ord_display() {
        use std::collections::HashSet;
        let kinds = [
            HarnessAttachmentKind::CrashPack,
            HarnessAttachmentKind::ReplayTrace,
            HarnessAttachmentKind::Trace,
            HarnessAttachmentKind::Other,
        ];
        // Display
        assert_eq!(format!("{}", kinds[0]), "crashpack");
        assert_eq!(format!("{}", kinds[1]), "replay_trace");
        assert_eq!(format!("{}", kinds[2]), "trace");
        assert_eq!(format!("{}", kinds[3]), "other");
        // Copy/Clone/Eq
        for &k in &kinds {
            let copied = k;
            let cloned = k;
            assert_eq!(copied, cloned);
        }
        // Hash
        let mut set = HashSet::new();
        for &k in &kinds {
            set.insert(k);
        }
        assert_eq!(set.len(), 4);
        // Ord (derive ordering: CrashPack < ReplayTrace < Trace < Other)
        assert!(HarnessAttachmentKind::CrashPack < HarnessAttachmentKind::ReplayTrace);
        assert!(HarnessAttachmentKind::ReplayTrace < HarnessAttachmentKind::Trace);
        assert!(HarnessAttachmentKind::Trace < HarnessAttachmentKind::Other);
        let mut sorted = [kinds[3], kinds[0], kinds[2], kinds[1]];
        sorted.sort();
        assert_eq!(sorted, kinds);
    }

    #[test]
    fn harness_attachment_ref_debug_clone_eq_hash() {
        use std::collections::HashSet;
        let ref1 = HarnessAttachmentRef::crashpack("crash.bin");
        let ref2 = HarnessAttachmentRef::replay_trace("replay.bin");
        let ref3 = HarnessAttachmentRef::trace("trace.ndjson");
        assert_eq!(ref1.kind, HarnessAttachmentKind::CrashPack);
        assert_eq!(ref2.kind, HarnessAttachmentKind::ReplayTrace);
        assert_eq!(ref3.kind, HarnessAttachmentKind::Trace);
        let cloned = ref1.clone();
        assert_eq!(cloned, ref1);
        assert_ne!(ref1, ref2);
        let dbg = format!("{ref1:?}");
        assert!(dbg.contains("HarnessAttachmentRef"));
        let mut set = HashSet::new();
        set.insert(ref1.clone());
        set.insert(ref2);
        set.insert(ref1); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn chaos_config_summary_debug_clone_copy_partial_eq() {
        let summary = ChaosConfigSummary {
            seed: 42,
            cancel_probability: 0.1,
            delay_probability: 0.2,
            io_error_probability: 0.05,
            wakeup_storm_probability: 0.01,
            budget_exhaust_probability: 0.03,
        };
        let copied = summary;
        let cloned = summary;
        assert_eq!(copied, cloned);
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("ChaosConfigSummary"));
    }

    #[test]
    fn obligation_leak_debug_clone_eq_display() {
        let leak = ObligationLeak {
            obligation: ObligationId::new_for_test(1, 0),
            kind: ObligationKind::SendPermit,
            holder: TaskId::from_arena(crate::util::ArenaIndex::new(1, 0)),
            region: RegionId::new_for_test(0, 0),
        };
        let cloned = leak.clone();
        assert_eq!(cloned, leak);
        let dbg = format!("{leak:?}");
        assert!(dbg.contains("ObligationLeak"));
        let display = format!("{leak}");
        assert!(display.contains("obligation="));
        assert!(display.contains("kind=SendPermit"));
        assert!(display.contains("holder="));
        assert!(display.contains("region="));
    }

    // ================================================================
    // CONFORMANCE TESTS: LabRuntime Deterministic Seed Reproduction
    // ================================================================
    //
    // Golden tests verifying the non-negotiable determinism invariants:
    // (1) Same seed produces byte-identical execution trace
    // (2) Virtual-time advances in same order across replays
    // (3) Scheduler lottery with same seed picks same tasks
    // (4) Chaos injection with same seed identical
    // (5) Cross-thread panic semantics preserved
    //
    // These conformance tests ensure LabRuntime provides reproducible
    // execution for debugging, testing, and formal verification.

    /// CONFORMANCE: Same seed produces byte-identical execution trace.
    ///
    /// Verifies that identical configuration and program produce identical
    /// trace fingerprints, event counts, and schedule certificates.
    #[test]
    fn conformance_identical_seed_identical_trace() {
        init_test("conformance_identical_seed_identical_trace");

        let seed = 42_u64;
        let config = LabConfig::new(seed).worker_count(2).max_steps(1000);

        // Run same program with same seed twice
        let mut reports = Vec::new();
        for run_id in 0..2 {
            let mut runtime = LabRuntime::new(config.clone());
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Create deterministic workload with multiple tasks
            for i in 0..5 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Simulate work with deterministic operations
                        for j in 0..10 {
                            futures_lite::future::yield_now().await;
                            if (i + j) % 3 == 0 {
                                let now =
                                    crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                                crate::time::sleep(now, Duration::from_millis(1)).await;
                            }
                        }
                        i * 100 + run_id
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            let report = runtime.run_until_quiescent_with_report();
            reports.push(report);
        }

        // Verify identical traces
        let report1 = &reports[0];
        let report2 = &reports[1];

        crate::assert_with_log!(
            report1.seed == report2.seed,
            "seeds should be identical",
            report1.seed,
            report2.seed
        );

        crate::assert_with_log!(
            report1.trace_fingerprint == report2.trace_fingerprint,
            "trace fingerprints should be identical",
            report1.trace_fingerprint,
            report2.trace_fingerprint
        );

        crate::assert_with_log!(
            report1.trace_certificate.event_hash == report2.trace_certificate.event_hash,
            "event hashes should be identical",
            report1.trace_certificate.event_hash,
            report2.trace_certificate.event_hash
        );

        crate::assert_with_log!(
            report1.trace_certificate.event_count == report2.trace_certificate.event_count,
            "event counts should be identical",
            report1.trace_certificate.event_count,
            report2.trace_certificate.event_count
        );

        crate::assert_with_log!(
            report1.trace_certificate.schedule_hash == report2.trace_certificate.schedule_hash,
            "schedule hashes should be identical",
            report1.trace_certificate.schedule_hash,
            report2.trace_certificate.schedule_hash
        );

        crate::test_complete!("conformance_identical_seed_identical_trace");
    }

    /// CONFORMANCE: Virtual-time advances in same order across replays.
    ///
    /// Verifies that virtual time progression and auto-advancement
    /// behavior is deterministic across runs with the same seed.
    #[test]
    fn conformance_virtual_time_deterministic_advancement() {
        init_test("conformance_virtual_time_deterministic_advancement");

        let config = LabConfig::new(123).worker_count(1);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let initial_time = runtime.now();

            // Create tasks that sleep for different durations to test time advancement
            let durations = [
                Duration::from_millis(10),
                Duration::from_millis(5),
                Duration::from_millis(15),
                Duration::from_millis(1),
            ];

            for (i, duration) in durations.iter().enumerate() {
                let dur = *duration;
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                        crate::time::sleep(now, dur).await;
                        i
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Use auto-advance to let virtual time progress deterministically
            let vtime_report = runtime.run_with_auto_advance();

            // Verify time advanced
            crate::assert_with_log!(
                vtime_report.time_end > initial_time,
                "virtual time should have advanced",
                vtime_report.time_end,
                initial_time
            );

            crate::assert_with_log!(
                vtime_report.auto_advances > 0,
                "should have auto-advanced virtual time",
                vtime_report.auto_advances,
                0
            );

            crate::assert_with_log!(
                vtime_report.termination == AutoAdvanceTermination::Quiescent,
                "should reach quiescence",
                vtime_report.termination,
                AutoAdvanceTermination::Quiescent
            );
        });

        crate::test_complete!("conformance_virtual_time_deterministic_advancement");
    }

    /// CONFORMANCE: Scheduler lottery with same seed picks same tasks.
    ///
    /// Verifies that scheduler decisions (task selection, worker assignment)
    /// are deterministic given the same random seed.
    #[test]
    fn conformance_scheduler_deterministic_lottery() {
        init_test("conformance_scheduler_deterministic_lottery");

        let config = LabConfig::new(456).worker_count(4);

        let mut schedule_sequences = Vec::new();

        // Run same workload multiple times to capture scheduler decisions
        for run in 0..2 {
            let mut runtime = LabRuntime::new(config.clone());
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let mut task_order = Vec::new();

            // Create many competing tasks to stress scheduler lottery
            for task_idx in 0..20 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Add some yield points to allow preemption
                        for _ in 0..3 {
                            futures_lite::future::yield_now().await;
                        }
                        task_idx
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Execute and capture schedule certificate
            runtime.run_until_quiescent();
            let cert = runtime.certificate();
            task_order.push((run, cert.decisions(), cert.hash()));
            schedule_sequences.push(task_order);
        }

        // Verify scheduler made same decisions across runs
        let seq1 = &schedule_sequences[0];
        let seq2 = &schedule_sequences[1];

        crate::assert_with_log!(
            seq1.len() == seq2.len(),
            "should have same number of scheduling decision points",
            seq1.len(),
            seq2.len()
        );

        for (i, ((_run1, count1, hash1), (_run2, count2, hash2))) in
            seq1.iter().zip(seq2.iter()).enumerate()
        {
            crate::assert_with_log!(
                count1 == count2,
                &format!("decision count should be identical at point {}", i),
                count1,
                count2
            );

            crate::assert_with_log!(
                hash1 == hash2,
                &format!("schedule hash should be identical at point {}", i),
                hash1,
                hash2
            );
        }

        crate::test_complete!("conformance_scheduler_deterministic_lottery");
    }

    /// CONFORMANCE: Chaos injection with same seed produces identical outcomes.
    ///
    /// Verifies that chaos injection (cancellation, delays, errors) is
    /// deterministically reproducible with the same chaos seed.
    #[test]
    fn conformance_chaos_injection_deterministic() {
        init_test("conformance_chaos_injection_deterministic");

        let chaos_config = crate::lab::chaos::ChaosConfig::new(789)
            .with_cancel_probability(0.1)
            .with_delay_probability(0.05)
            .with_io_error_probability(0.02);
        let config = LabConfig::new(999).with_chaos(chaos_config);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Create workload susceptible to chaos injection
            for i in 0..10 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Multiple poll points where chaos can be injected
                        for j in 0..20 {
                            futures_lite::future::yield_now().await;
                            if j % 5 == 0 {
                                let now =
                                    crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                                crate::time::sleep(now, Duration::from_millis(1)).await;
                            }
                        }
                        i
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            // Verify chaos was actually applied
            let chaos_stats = runtime.chaos_stats();
            let total_decisions = chaos_stats.decision_points;

            crate::assert_with_log!(
                total_decisions > 0,
                "chaos should have made some decisions",
                total_decisions,
                0
            );
        });

        crate::test_complete!("conformance_chaos_injection_deterministic");
    }

    /// CONFORMANCE: Cross-thread panic semantics are preserved deterministically.
    ///
    /// Verifies that panic propagation and cleanup across workers/regions
    /// follows the same deterministic pattern with identical seeds.
    #[test]
    fn conformance_panic_semantics_deterministic() {
        init_test("conformance_panic_semantics_deterministic");

        let config = LabConfig::new(333)
            .worker_count(3)
            .panic_on_leak(false)
            .max_steps(10_000); // Fail diagnostically instead of hanging if panic cleanup regresses

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Create tasks where one will panic
            for i in 0..5 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Task 2 will deterministically panic
                        assert!(i != 2, "deterministic panic in task {}", i);

                        // Other tasks continue working
                        for _j in 0..10 {
                            futures_lite::future::yield_now().await;
                        }
                        i * 10
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // The lab trace no longer exposes a dedicated `TaskPanicked` data
            // variant. Drive the panic-bearing run to quiescence once and
            // inspect that same run's report rather than a second already-idle
            // pass.
            let report = runtime.run_until_quiescent_with_report();
            let trace_events = runtime.trace().snapshot();
            let complete_events = trace_events
                .iter()
                .filter(|event| event.kind == TraceEventKind::Complete)
                .count();

            crate::assert_with_log!(
                complete_events > 0,
                "should have recorded task completion activity",
                complete_events,
                0
            );

            // Verify deterministic cleanup occurred
            crate::assert_with_log!(
                report.quiescent,
                "runtime should reach quiescence despite panic",
                report.quiescent,
                false
            );
        });

        crate::test_complete!("conformance_panic_semantics_deterministic");
    }

    /// CONFORMANCE: Comprehensive multi-run determinism verification.
    ///
    /// Combines all previous conformance aspects into a stress test
    /// that verifies determinism across many execution runs.
    #[test]
    fn conformance_comprehensive_determinism_stress() {
        init_test("conformance_comprehensive_determinism_stress");

        let chaos_config = crate::lab::chaos::ChaosConfig::new(555)
            .with_cancel_probability(0.05)
            .with_delay_probability(0.03);
        let config = LabConfig::new(777)
            .worker_count(4)
            .with_chaos(chaos_config)
            .max_steps(5000);

        // Use assert_deterministic_multi for extra confidence
        crate::lab::assert_deterministic_multi(&config, 3, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Complex workload mixing all runtime features
            for i in 0..15 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Mix of operations: yields, sleeps, work
                        for j in 0..30 {
                            match (i + j) % 4 {
                                0 => futures_lite::future::yield_now().await,
                                1 => {
                                    let now =
                                        crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                                    crate::time::sleep(now, Duration::from_millis(j as u64 % 5))
                                        .await;
                                }
                                2 => {
                                    // Simulate CPU work
                                    let mut sum = 0_u64;
                                    for k in 0..100 {
                                        sum = sum.wrapping_add(k);
                                    }
                                    let _ = sum;
                                }
                                _ => futures_lite::future::yield_now().await,
                            }
                        }
                        i * 1000 + 42
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Use auto-advance for time progression
            let vtime_report = runtime.run_with_auto_advance();

            crate::assert_with_log!(
                vtime_report.termination == AutoAdvanceTermination::Quiescent,
                "comprehensive workload should reach quiescence",
                vtime_report.termination,
                AutoAdvanceTermination::Quiescent
            );
        });

        crate::test_complete!("conformance_comprehensive_determinism_stress");
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn non_test_lab_runtime_paths_do_not_use_stray_stdout_debug_prints() {
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file!()))
                .expect("lab runtime source must be readable");

        for message in [
            "LabScheduler already scheduled {task:?}",
            "LabScheduler scheduling {task:?}",
            "Executing {:?} at step {}",
            "rng_value = {}, worker_hint = {}",
        ] {
            let stdout_call = format!("print{}!(\"{message}\"", "ln");
            assert!(
                !source.contains(&stdout_call),
                "non-test LabRuntime debug print regressed: {message}"
            );
        }
    }

    #[test]
    fn report_feeds_the_oracle_eprocess_monitor() {
        let mut lab = LabRuntime::new(LabConfig::new(7).max_steps(10_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                crate::runtime::yield_now::yield_now().await;
            })
            .expect("create task");
        lab.scheduler.lock().schedule(task_id, 0);

        let run = lab.run_until_quiescent_with_report();
        assert!(run.steps_delta > 0, "the run advanced the lab");
        let reported: Vec<&str> = ["task_leak", "obligation_leak", "quiescence"]
            .into_iter()
            .filter(|name| run.oracle_report.entry(name).is_some())
            .collect();
        assert!(
            !reported.is_empty(),
            "the report covers a monitored invariant"
        );
        let observations = |lab: &LabRuntime, name: &str| {
            lab.oracles
                .eprocess_monitor
                .as_ref()
                .expect("the standard oracle suite has an e-process monitor")
                .process(name)
                .expect("monitored invariant")
                .observations
        };
        for name in &reported {
            assert_eq!(
                observations(&lab, name),
                1,
                "{name}: the run is observed once"
            );
        }

        // A plain report does not advance the lab, so it adds no evidence.
        let _ = lab.report();
        for name in &reported {
            assert_eq!(
                observations(&lab, name),
                1,
                "{name}: re-reporting the same state is not a new observation"
            );
        }
    }

    /// A task spawning into its own region after the region began closing is
    /// denied; the denial releases the region's pending-spawn credit and must
    /// re-advance the region, as the native scheduler does. The lab left the
    /// region Closing, so its close never resolved (a lab-only hang).
    #[test]
    fn a_denied_spawn_re_advances_its_closing_region() {
        let mut lab = LabRuntime::new(LabConfig::new(0xD3_41ED).max_steps(10_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, mut gate) = crate::channel::oneshot::channel::<()>();
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = std::sync::Arc::clone(&closed);
        let (owner, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = crate::cx::Cx::current().expect("owner Cx");
                let child = cx
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .expect("open child region");
                let _late = child
                    .cx()
                    .spawn(move |task_cx| async move {
                        gate.recv_uninterruptible().await.expect("release");
                        let _ = task_cx.spawn(|_| async {});
                    })
                    .expect("spawn the late spawner");
                let _ = child.close().await;
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .expect("create owner");
        lab.scheduler.lock().schedule(owner, 0);
        lab.run_until_idle();
        release.send_blocking(()).expect("release the late spawner");
        lab.run_until_quiescent();
        assert!(
            closed.load(std::sync::atomic::Ordering::SeqCst),
            "the closing region closed after the denied spawn"
        );
    }
