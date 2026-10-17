    use super::*;
    use crate::runtime::RuntimeBuilder;
    use std::sync::atomic::AtomicUsize;

    fn block_on<F: Future>(future: F) -> F::Output {
        RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(future)
    }

    /// A task waker that counts its wakes.
    #[derive(Default)]
    struct CountingWake(AtomicUsize);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl CountingWake {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn fibers_borrow_the_callers_stack_and_return_results() {
        let words = vec!["structured".to_string(), "concurrency".to_string()];
        let words = &words;
        let total = block_on(scope(|s| async move {
            let a = s.spawn(async move { words[0].len() });
            let b = s.spawn(async move { words[1].len() });
            a.await.expect("a") + b.await.expect("b")
        }));
        assert_eq!(total, 21);
    }

    #[test]
    fn scope_waits_for_fibers_whose_handles_were_dropped() {
        let finished = AtomicUsize::new(0);
        let finished_ref = &finished;
        block_on(scope(|s| async move {
            for _ in 0..100 {
                drop(s.spawn(async move {
                    crate::runtime::yield_now().await;
                    finished_ref.fetch_add(1, Ordering::SeqCst);
                }));
            }
        }));
        assert_eq!(finished.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn fibers_interleave_rather_than_run_to_completion_one_by_one() {
        let log = Mutex::new(Vec::new());
        let log_ref = &log;
        block_on(scope(|s| async move {
            for id in 0..3 {
                drop(s.spawn(async move {
                    log_ref.lock().push((id, 0));
                    crate::runtime::yield_now().await;
                    log_ref.lock().push((id, 1));
                }));
            }
        }));
        let log = log.into_inner();
        let first_round: Vec<_> = log[..3].iter().map(|(_, step)| *step).collect();
        assert_eq!(
            first_round,
            vec![0, 0, 0],
            "every fiber starts before any resumes: {log:?}"
        );
        assert_eq!(log.len(), 6);
    }

    #[test]
    fn a_self_waking_fiber_does_not_monopolize_the_scope_poll() {
        // A fiber that yields forever would hang a scope that re-polled
        // self-woken fibers within one poll; here the sibling still finishes
        // and the scope stops the spinner through a flag.
        let stop = AtomicBool::new(false);
        let spins = AtomicUsize::new(0);
        let (stop_ref, spins_ref) = (&stop, &spins);
        block_on(scope(|s| async move {
            drop(s.spawn(async move {
                while !stop_ref.load(Ordering::SeqCst) {
                    spins_ref.fetch_add(1, Ordering::SeqCst);
                    crate::runtime::yield_now().await;
                }
            }));
            let worker = s.spawn(async move {
                for _ in 0..10 {
                    crate::runtime::yield_now().await;
                }
                stop_ref.store(true, Ordering::SeqCst);
            });
            worker.await.expect("worker fiber");
        }));
        assert!(spins.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn a_fiber_panic_is_reported_through_its_handle() {
        let result = block_on(scope(|s| async move {
            let handle = s.spawn(async {
                let fail = std::hint::black_box(true);
                assert!(!fail, "boom");
                1
            });
            handle.await
        }));
        match result {
            Err(JoinError::Panicked(payload)) => assert!(payload.message().contains("boom")),
            other => panic!("expected a panicked join, got {other:?}"),
        }
    }

    #[test]
    fn an_unobserved_fiber_panic_is_raised_when_the_scope_finishes() {
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(scope(|s| async move {
                drop(s.spawn(async {
                    let fail = std::hint::black_box(true);
                    assert!(!fail, "unobserved");
                }));
            }));
        }));
        let payload = raised.expect_err("the unobserved panic must surface");
        let message = crate::cx::scope::payload_to_string(&payload);
        assert!(message.contains("unobserved"), "{message}");
    }

    /// Two fibers panic in the same pass and the body observes only the
    /// first: the second panic must still surface when the scope finishes.
    #[test]
    fn a_second_unobserved_panic_is_raised_after_the_first_is_observed() {
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(scope(|s| async move {
                let first = s.spawn(async {
                    let fail = std::hint::black_box(true);
                    assert!(!fail, "first");
                });
                let second = s.spawn(async {
                    let fail = std::hint::black_box(true);
                    assert!(!fail, "second");
                });
                assert!(matches!(first.await, Err(JoinError::Panicked(_))));
                drop(second);
            }));
        }));
        let payload = raised.expect_err("the second, unobserved panic must surface");
        let message = crate::cx::scope::payload_to_string(&payload);
        assert!(message.contains("second"), "{message}");
    }

    #[test]
    fn many_fibers_complete_with_slot_reuse() {
        let sum = block_on(scope(|s| async move {
            let mut total = 0usize;
            for round in 0..10 {
                let handles: Vec<_> = (0..100)
                    .map(|i| s.spawn(async move { round * 100 + i }))
                    .collect();
                for handle in handles {
                    total += handle.await.expect("fiber");
                }
            }
            total
        }));
        assert_eq!(sum, (0..1000).sum::<usize>());
    }

    #[test]
    fn a_finished_fibers_slot_and_wake_handle_are_reused() {
        let slots = block_on(scope(|s| async move {
            for i in 0..100 {
                assert_eq!(s.spawn(async move { i }).await.expect("fiber"), i);
            }
            s.state.set.lock().slots.len()
        }));
        assert_eq!(slots, 1, "sequential fibers keep reusing one slot");
    }

    #[test]
    fn a_fiber_can_start_siblings_and_the_scope_waits_for_them() {
        let finished = AtomicUsize::new(0);
        let finished_ref = &finished;
        let observed = block_on(scope(|s| async move {
            let spawner = s.clone();
            let parent = s.spawn(async move {
                crate::runtime::yield_now().await;
                for _ in 0..5 {
                    drop(spawner.spawn(async move {
                        crate::runtime::yield_now().await;
                        finished_ref.fetch_add(1, Ordering::SeqCst);
                    }));
                }
            });
            parent.await.expect("parent fiber");
            // The siblings were started but have not run to completion yet.
            s.live()
        }));
        assert_eq!(observed, 5, "the body returned while siblings were live");
        assert_eq!(finished.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn wakes_inside_the_scope_poll_rewake_the_task_once() {
        let wakes = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(scope(|s| async move {
            for _ in 0..10 {
                drop(s.spawn(crate::runtime::yield_now()));
            }
            std::future::pending::<()>().await;
        }));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            wakes.count(),
            1,
            "ten fibers that woke themselves during the pass re-wake the task once"
        );
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(wakes.count(), 1, "the second pass finished every fiber");
    }

    #[test]
    fn a_spawn_from_outside_the_scope_poll_wakes_the_task() {
        let wakes = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let escaped = Mutex::new(None);
        let escaped_ref = &escaped;
        let mut future = pin!(scope(|s| async move {
            *escaped_ref.lock() = Some(s);
            std::future::pending::<()>().await;
        }));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(wakes.count(), 0);
        let outside = escaped.lock().take().expect("escaped handle");
        let mut handle = pin!(outside.spawn(async { 5 }));
        assert_eq!(wakes.count(), 1, "the task must learn about the new fiber");
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(outside.live(), 0, "the woken scope ran the fiber");
        match handle.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(value)) => assert_eq!(value, 5),
            other => panic!("expected the fiber's value, got {other:?}"),
        }
    }

    #[test]
    fn spawning_through_a_handle_that_escaped_the_scope_panics() {
        let escaped = block_on(scope(|s| async move { s }));
        assert_eq!(escaped.live(), 0);
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(escaped.spawn(async {}));
        }));
        let payload = raised.expect_err("a finished scope must refuse new fibers");
        let message = crate::cx::scope::payload_to_string(&payload);
        assert!(message.contains("after its scope finished"), "{message}");
        assert_eq!(escaped.live(), 0, "the refused fiber was not queued");
    }

    #[test]
    fn dropping_an_unfinished_scope_drops_its_fibers() {
        struct SetOnDrop<'a>(&'a AtomicBool);
        impl Drop for SetOnDrop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = AtomicBool::new(false);
        let dropped_ref = &dropped;
        let escaped = Mutex::new(None);
        let escaped_ref = &escaped;
        {
            let mut future = pin!(scope(|s| async move {
                *escaped_ref.lock() = Some(s.clone());
                drop(s.spawn(async move {
                    let _guard = SetOnDrop(dropped_ref);
                    std::future::pending::<()>().await;
                }));
                std::future::pending::<()>().await;
            }));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            assert!(!dropped.load(Ordering::SeqCst), "the fiber is parked");
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "dropping the scope future must drop its fibers even though a handle escaped"
        );
        let escaped = escaped.into_inner().expect("escaped handle");
        assert_eq!(escaped.live(), 0);
    }

    /// A handle that outlives its scope future must not wait forever: when
    /// the scope future is dropped, the fiber's handle is woken and resolves
    /// as cancelled, whether the fiber had started or not.
    #[test]
    fn handles_that_outlive_a_dropped_scope_are_woken_and_cancelled() {
        let escaped = Mutex::new(None);
        let escaped_ref = &escaped;
        let wakes = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let (mut started, mut unstarted) = {
            let mut future = pin!(scope(|s| async move {
                let started = s.spawn(std::future::pending::<u32>());
                *escaped_ref.lock() = Some((s.clone(), started));
                std::future::pending::<()>().await;
            }));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            let (scope_handle, mut started) = escaped_ref.lock().take().expect("escaped");
            assert!(
                Pin::new(&mut started)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending(),
                "the started fiber is parked"
            );
            // Spawned from outside the scope's poll: never polled.
            let unstarted = scope_handle.spawn(async { 7u32 });
            (started, unstarted)
        };
        assert_eq!(
            wakes.count(),
            1,
            "dropping the scope wakes the waiting handle"
        );
        for (name, handle) in [("started", &mut started), ("unstarted", &mut unstarted)] {
            match Pin::new(handle).poll(&mut Context::from_waker(&waker)) {
                Poll::Ready(Err(JoinError::Cancelled(_))) => {}
                other => panic!("{name}: expected a cancelled join, got {other:?}"),
            }
        }
    }

    #[test]
    fn scope_future_is_send_for_send_fibers() {
        fn assert_send<T: Send>(_: &T) {}
        let data = [1u32, 2, 3];
        let data = &data;
        let future = scope(|s| async move {
            let h = s.spawn(async move { data.iter().sum::<u32>() });
            h.await.expect("sum")
        });
        assert_send(&future);
        assert_eq!(block_on(future), 6);
    }

    #[test]
    fn scope_runs_inside_a_send_static_task_over_task_local_borrows() {
        // The shape of a spawned task: the future owns its data, is `Send +
        // 'static`, and its fibers borrow that data. A higher-ranked body
        // bound fails to compile here (rust-lang/rust#100013).
        fn require_send_static<F: Future + Send + 'static>(future: F) -> F {
            future
        }
        let task = require_send_static(async move {
            let inputs: Vec<usize> = (0..64).collect();
            let inputs = &inputs;
            scope(|s| async move {
                let handles: Vec<_> = (0..inputs.len())
                    .map(|i| s.spawn(async move { inputs[i] * 2 }))
                    .collect();
                let mut total = 0;
                for handle in handles {
                    total += handle.await.expect("fiber");
                }
                total
            })
            .await
        });
        assert_eq!(block_on(task), (0..64).map(|i| i * 2).sum::<usize>());
    }

    // --- Per-fiber cancellation (br-asupersync-issue65-criticisms-kpmoy5.3.1/.3.2) ---

    /// Runs `future` with `task_cx` as the ambient context, outside any
    /// runtime: the scope takes it as its task's context.
    fn block_on_in<F: Future>(task_cx: &Cx, future: F) -> F::Output {
        let _current = Cx::set_current(Some(task_cx.clone()));
        futures_lite::future::block_on(future)
    }

    /// Runs `test` on a scratch thread and fails, instead of hanging, if a
    /// cancellation it waits for never arrives.
    fn within_watchdog<T: Send + 'static>(test: impl FnOnce() -> T + Send + 'static) -> T {
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(test());
        });
        match result.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(value) => value,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("a fiber waited 10 s for a cancellation that never reached it")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the test thread panicked")
            }
        }
    }

    /// Resolves with the ambient context's cancellation reason (inside a
    /// fiber, the fiber's own), parking on its cancel waker until then.
    fn until_cancelled() -> impl Future<Output = CancelReason> {
        poll_fn(|task_cx| {
            let cx = Cx::current().expect("an ambient context");
            if !cx.is_cancel_requested() {
                cx.register_cancel_waker(task_cx.waker());
                if !cx.is_cancel_requested() {
                    return Poll::Pending;
                }
            }
            Poll::Ready(
                cx.cancel_reason()
                    .expect("a cancelled context has a reason"),
            )
        })
    }

    #[test]
    fn inside_a_fiber_the_ambient_context_is_the_fibers_own() {
        let task_cx = Cx::for_testing();
        let task_ref = &task_cx;
        block_on_in(&task_cx, async {
            scope(|s| async move {
                s.spawn(async move {
                    let fiber_cx = Cx::current().expect("the fiber's context");
                    assert_eq!(fiber_cx.task_id(), task_ref.task_id(), "same task");
                    assert_eq!(fiber_cx.region_id(), task_ref.region_id(), "same region");
                    fiber_cx.cancel_with(CancelKind::User, Some("the fiber's own"));
                    assert!(fiber_cx.is_cancel_requested());
                })
                .await
                .expect("fiber");
            })
            .await;
        });
        assert!(
            !task_cx.is_cancel_requested(),
            "cancelling a fiber's context does not cancel the task"
        );
    }

    #[test]
    fn a_fiber_handle_cancels_only_its_fiber() {
        let (first, second, task_cancelled) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let (first, second) = block_on_in(&task_cx, async {
                scope(|s| async move {
                    let a = s.spawn(until_cancelled());
                    let b = s.spawn(until_cancelled());
                    a.cancel();
                    let first = a.await.expect("a");
                    assert_eq!(s.live(), 1, "b is still waiting");
                    b.cancel();
                    (first, b.await.expect("b"))
                })
                .await
            });
            (first, second, task_cx.is_cancel_requested())
        });
        assert_eq!(first.kind, CancelKind::User);
        assert_eq!(second.kind, CancelKind::User);
        assert!(!task_cancelled, "the task is not cancelled");
    }

    #[test]
    fn the_tasks_cancellation_reaches_every_fiber() {
        let reasons = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let waiting: Vec<_> = (0..3).map(|_| s.spawn(until_cancelled())).collect();
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    let mut reasons = Vec::new();
                    for handle in waiting {
                        reasons.push(handle.await.expect("fiber"));
                    }
                    reasons
                })
                .await
            })
        });
        assert_eq!(reasons.len(), 3);
        for reason in reasons {
            assert_eq!(reason.kind, CancelKind::Shutdown, "the task's own reason");
        }
    }

    #[test]
    fn a_fiber_started_after_the_task_was_cancelled_starts_cancelled() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            task_cx.cancel_with(CancelKind::User, Some("cancelled before the fiber"));
            block_on_in(&task_cx, async {
                scope(|s| async move { s.spawn(until_cancelled()).await.expect("fiber") }).await
            })
        });
        assert_eq!(reason.kind, CancelKind::User);
    }

    #[test]
    fn a_panicking_fiber_cancels_its_siblings() {
        let (panicked, sibling, task_cancelled) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let (panicked, sibling) = block_on_in(&task_cx, async {
                scope(|s| async move {
                    let sibling = s.spawn(until_cancelled());
                    let failing = s.spawn(async {
                        crate::runtime::yield_now().await;
                        panic!("this fiber fails");
                    });
                    let panicked = failing.await.is_err();
                    (panicked, sibling.await.expect("sibling"))
                })
                .await
            });
            (panicked, sibling, task_cx.is_cancel_requested())
        });
        assert!(panicked, "the failing fiber's handle reports its panic");
        assert_eq!(
            sibling.kind,
            CancelKind::FailFast,
            "fail-fast sibling cancel"
        );
        assert!(!task_cancelled, "the task is not cancelled");
    }

    // --- Contexts built on first use (br-asupersync-98569u) ---

    /// Yields twice without reading the ambient context, then waits on the
    /// fiber's own context until it is cancelled.
    async fn read_context_late() -> CancelReason {
        crate::runtime::yield_now().await;
        crate::runtime::yield_now().await;
        until_cancelled().await
    }

    #[test]
    fn a_fiber_that_never_reads_its_context_derives_none() {
        let task_cx = Cx::for_testing();
        let (silent_built, reader_built) = block_on_in(&task_cx, async {
            scope(|s| async move {
                let silent = s.spawn(async { 1 });
                let reader = s.spawn(async { Cx::current().is_some() });
                let silent_ctx = Arc::clone(silent.ctx.as_ref().expect("a task scope's cell"));
                let reader_ctx = Arc::clone(reader.ctx.as_ref().expect("a task scope's cell"));
                assert_eq!(silent.await.expect("silent"), 1);
                assert!(reader.await.expect("reader"), "the fiber has a context");
                let built = |ctx: &FiberCtx| ctx.cx.get().is_some();
                (built(&silent_ctx), built(&reader_ctx))
            })
            .await
        });
        assert!(
            !silent_built,
            "a fiber that never read its context has none"
        );
        assert!(
            reader_built,
            "reading Cx::current() built the fiber's context"
        );
    }

    #[test]
    fn every_read_in_a_fiber_sees_the_same_context() {
        let task_cx = Cx::for_testing();
        let (same, task_cancelled) = block_on_in(&task_cx, async {
            let same = scope(|s| async move {
                s.spawn(async {
                    let first = Cx::current().expect("the fiber's context");
                    crate::runtime::yield_now().await;
                    let later = Cx::current().expect("the fiber's context");
                    first.cancel_fast(CancelKind::User);
                    later.is_cancel_requested()
                })
                .await
                .expect("fiber")
            })
            .await;
            (same, Cx::current().expect("task").is_cancel_requested())
        });
        assert!(same, "both reads see one context, across polls");
        assert!(!task_cancelled, "and it is not the task's");
    }

    #[test]
    fn with_current_in_a_fiber_borrows_the_fibers_own_context() {
        let task_cx = Cx::for_testing();
        let (cancelled_inside, task_cancelled) = block_on_in(&task_cx, async {
            let inside = scope(|s| async move {
                s.spawn(async {
                    Cx::with_current(|cx| cx.cancel_fast(CancelKind::User))
                        .expect("the fiber's context");
                    Cx::current()
                        .expect("the fiber's context")
                        .is_cancel_requested()
                })
                .await
                .expect("fiber")
            })
            .await;
            (inside, Cx::current().expect("task").is_cancel_requested())
        });
        assert!(cancelled_inside, "with_current reached the fiber's context");
        assert!(!task_cancelled, "not the task's");
    }

    /// The task is cancelled, then the fiber's handle, both before the fiber
    /// reads its context. Replayed in that order the task's `Shutdown` stays
    /// (the handle's weaker `User` cannot replace it), as on a context built
    /// at spawn. Replayed the other way, `User` would stick: a cancelled
    /// context ignores a later inherit.
    #[test]
    fn cancellations_before_the_first_read_apply_in_order() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fiber = s.spawn(read_context_late());
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    crate::runtime::yield_now().await;
                    fiber.cancel();
                    fiber.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::Shutdown, "the first cancellation");
    }

    #[test]
    fn a_handle_cancel_before_the_fiber_reads_its_context_reaches_it() {
        let (reason, task_cancelled) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let reason = block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fiber = s.spawn(read_context_late());
                    fiber.cancel();
                    fiber.await.expect("fiber")
                })
                .await
            });
            (reason, task_cx.is_cancel_requested())
        });
        assert_eq!(reason.kind, CancelKind::User, "the handle's cancellation");
        assert!(
            !task_cancelled,
            "cancelling a fiber does not cancel the task"
        );
    }

    #[test]
    fn the_tasks_cancellation_reaches_a_fiber_that_reads_its_context_later() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fiber = s.spawn(read_context_late());
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    fiber.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::Shutdown, "the task's own reason");
    }

    #[test]
    fn a_panic_cancels_a_sibling_that_reads_its_context_later() {
        let (panicked, sibling) = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let sibling = s.spawn(read_context_late());
                    let failing = s.spawn(async {
                        let fail = std::hint::black_box(true);
                        assert!(!fail, "this fiber fails");
                    });
                    let panicked = failing.await.is_err();
                    (panicked, sibling.await.expect("sibling"))
                })
                .await
            })
        });
        assert!(panicked, "the failing fiber's handle reports its panic");
        assert_eq!(
            sibling.kind,
            CancelKind::FailFast,
            "the sibling read its context after the panic and saw the fail-fast"
        );
    }

    #[test]
    fn without_a_task_context_fibers_run_without_one() {
        let ran = futures_lite::future::block_on(scope(|s| async move {
            let handle = s.spawn(async { Cx::current().is_none() });
            handle.cancel();
            handle.await.expect("fiber")
        }));
        assert!(ran, "no ambient context, and cancel() is a no-op");
    }

    // --- Native task abort (br-asupersync-issue65-criticisms-kpmoy5.3.3) ---

    /// Parks on the ambient (fiber) context's cancel waker, counting itself
    /// in `parked` once it is parked, and records the cancellation kind it
    /// then observes in `seen`.
    fn parked_until_cancelled(
        parked: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<CancelKind>>>,
    ) -> impl Future<Output = ()> {
        let mut counted = false;
        poll_fn(move |task_cx| {
            let cx = Cx::current().expect("the fiber's context");
            if !cx.is_cancel_requested() {
                cx.register_cancel_waker(task_cx.waker());
                if !cx.is_cancel_requested() {
                    if !counted {
                        counted = true;
                        parked.fetch_add(1, Ordering::SeqCst);
                    }
                    return Poll::Pending;
                }
            }
            let reason = cx
                .cancel_reason()
                .expect("a cancelled context has a reason");
            seen.lock().push(reason.kind);
            Poll::Ready(())
        })
    }

    /// Spawns a task whose body runs a scope with two fibers parked on their
    /// own contexts, proves both are parked, aborts the task, and returns
    /// the cancellation kinds the fibers observed.
    fn abort_a_task_with_parked_fibers(builder: RuntimeBuilder) -> Vec<CancelKind> {
        let runtime = builder.build().expect("runtime");
        let parked = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (parked_in_task, seen_in_task) = (Arc::clone(&parked), Arc::clone(&seen));
        runtime.block_on(async move {
            let cx = Cx::current().expect("the root context");
            let mut handle = cx
                .spawn(move |_task_cx| async move {
                    scope(|s| async move {
                        let waits: Vec<_> = (0..2)
                            .map(|_| {
                                s.spawn(parked_until_cancelled(
                                    Arc::clone(&parked_in_task),
                                    Arc::clone(&seen_in_task),
                                ))
                            })
                            .collect();
                        for wait in waits {
                            wait.await.expect("fiber");
                        }
                    })
                    .await;
                })
                .expect("spawn the task");
            while parked.load(Ordering::SeqCst) < 2 {
                crate::runtime::yield_now().await;
            }
            handle.abort_with_reason(
                CancelReason::new(CancelKind::Shutdown).with_message("abort the scope's task"),
            );
            // Cancelled or Ok: either way the task finishes after its fibers drain.
            let _ = handle.join(&cx).await;
        });
        seen.lock().clone()
    }

    #[test]
    fn aborting_the_task_reaches_its_parked_fibers_current_thread() {
        let seen =
            within_watchdog(|| abort_a_task_with_parked_fibers(RuntimeBuilder::current_thread()));
        assert_eq!(
            seen,
            vec![CancelKind::Shutdown; 2],
            "both fibers see the task's reason"
        );
    }

    #[test]
    fn aborting_the_task_reaches_its_parked_fibers_four_workers() {
        let seen = within_watchdog(|| {
            abort_a_task_with_parked_fibers(RuntimeBuilder::new().worker_threads(4))
        });
        assert_eq!(
            seen,
            vec![CancelKind::Shutdown; 2],
            "both fibers see the task's reason"
        );
    }

    // --- Borrowing, forgetting and lab determinism (kpmoy5.3.3) ---

    #[test]
    fn fibers_mutate_disjoint_borrows_and_use_non_send_values_between_awaits() {
        let mut data = vec![0_u32; 4];
        let mut total = 0_usize;
        {
            let (left, right) = data.split_at_mut(2);
            let total = &mut total;
            block_on(scope(|s| async move {
                let a = s.spawn(async move {
                    for value in left.iter_mut() {
                        *value += 1;
                        crate::runtime::yield_now().await;
                    }
                });
                let b = s.spawn(async move {
                    for value in right.iter_mut() {
                        *value += 2;
                        crate::runtime::yield_now().await;
                    }
                    // A !Send value is fine while no await holds it.
                    let local = std::rc::Rc::new(5_usize);
                    *local
                });
                a.await.expect("left half");
                *total += b.await.expect("right half");
            }));
        }
        assert_eq!(data, [1, 1, 2, 2]);
        assert_eq!(total, 5);
    }

    #[test]
    fn forgetting_a_started_scope_future_is_sound_and_ends_its_borrow() {
        let mut data = vec![1, 2, 3];
        {
            let borrowed = &data;
            let mut started = Box::pin(scope(|s| async move {
                s.spawn(async move {
                    std::future::pending::<()>().await;
                    borrowed.len()
                })
                .await
                .expect("never resolves")
            }));
            let mut task = Context::from_waker(Waker::noop());
            assert!(
                started.as_mut().poll(&mut task).is_pending(),
                "the fiber is parked"
            );
            // Leaks the scope and its parked fiber: nothing runs again, and
            // nothing panics.
            std::mem::forget(started);
        }
        // The borrow ended with the forgotten future.
        data.push(4);
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    // The body returns the fiber's handle on purpose: the test is about a
    // handle that leaves the scope body.
    #[allow(clippy::async_yields_async)]
    fn a_handle_that_leaves_the_body_still_yields_its_result() {
        let handle = block_on(scope(|s| async move { s.spawn(async { 7_u8 }) }));
        assert_eq!(block_on(handle).expect("the scope waited for the fiber"), 7);
    }

    /// Logs each name, yielding after each one.
    async fn logged_steps(log: Arc<Mutex<Vec<&'static str>>>, names: &'static [&'static str]) {
        for &name in names {
            log.lock().push(name);
            crate::runtime::yield_now().await;
        }
    }

    /// One lab run: a task runs a scope whose fibers interleave while a third
    /// parks until cancelled, and the owner aborts the task once that fiber
    /// is parked. Returns the trace fingerprint, the fibers' step log and the
    /// cancellation kind the parked fiber saw.
    fn lab_fiber_run(seed: u64) -> (u64, Vec<&'static str>, Vec<CancelKind>) {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::Budget;

        let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let log = Arc::new(Mutex::new(Vec::new()));
        let parked = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (log_in_task, parked_in_task, seen_in_task) =
            (Arc::clone(&log), Arc::clone(&parked), Arc::clone(&seen));
        let (owner, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task context");
                let (log_in_scope, parked_in_scope) =
                    (Arc::clone(&log_in_task), Arc::clone(&parked_in_task));
                let mut worker = cx
                    .spawn(move |task_cx| async move {
                        scope(|s| async move {
                            let a = s.spawn(logged_steps(
                                Arc::clone(&log_in_scope),
                                &["a0", "a1", "a2"],
                            ));
                            let b = s.spawn(logged_steps(Arc::clone(&log_in_scope), &["b0", "b1"]));
                            let c = s.spawn(parked_until_cancelled(parked_in_scope, seen_in_task));
                            for handle in [a, b, c] {
                                handle.await.expect("fiber");
                            }
                        })
                        .await;
                        // Acknowledge the abort, as a cooperative task does.
                        let _ = task_cx.checkpoint();
                    })
                    .expect("spawn the worker");
                while parked_in_task.load(Ordering::SeqCst) < 1 || log_in_task.lock().len() < 5 {
                    crate::runtime::yield_now().await;
                }
                worker.abort_with_reason(CancelReason::new(CancelKind::Shutdown));
                let _ = worker.join(&cx).await;
            })
            .expect("create the owner");
        lab.scheduler.lock().schedule(owner, 0);
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "seed {seed:#x}: {report:?}");
        assert_eq!(lab.state.live_task_count(), 0, "seed {seed:#x}");
        let steps = log.lock().clone();
        let kinds = seen.lock().clone();
        (report.trace_fingerprint, steps, kinds)
    }

    #[test]
    fn lab_fiber_runs_replay_identically_per_seed() {
        let mut step_logs = Vec::new();
        for seed in [0xF1BE_0001_u64, 0xF1BE_0002] {
            let first = lab_fiber_run(seed);
            let second = lab_fiber_run(seed);
            assert_eq!(first, second, "seed {seed:#x} replays identically");
            assert_eq!(first.2, [CancelKind::Shutdown], "seed {seed:#x}");
            step_logs.push(first.1);
        }
        // The interleaving inside one task belongs to the scope, not to the
        // scheduler: it is the same under every seed.
        assert_eq!(step_logs[0], ["a0", "b0", "a1", "b1", "a2"]);
        assert_eq!(step_logs[0], step_logs[1]);
    }

    #[test]
    fn an_obligation_held_by_a_parked_fiber_is_a_futurelock_of_its_task() {
        use crate::lab::runtime::InvariantViolation;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::Budget;

        let mut lab = LabRuntime::new(
            LabConfig::new(0xF1BE_0F17)
                .futurelock_max_idle_steps(64)
                .panic_on_futurelock(false)
                .max_steps(100_000),
        );
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, mut released) = crate::channel::oneshot::channel::<()>();
        let (holder, _holder_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let (tx, _rx) = crate::channel::mpsc::channel::<u8>(1);
                scope(|s| async move {
                    s.spawn(async move {
                        let cx = Cx::current().expect("the fiber's context");
                        let permit = tx.reserve(&cx).await.expect("capacity");
                        // Parked while the permit's obligation is pending.
                        released.recv(&cx).await.expect("released");
                        permit.try_send(7).expect("the receiver is alive");
                    })
                    .await
                    .expect("fiber");
                })
                .await;
            })
            .expect("create the holder");
        let (ticker, _ticker_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                for _ in 0..256 {
                    crate::runtime::yield_now().await;
                }
            })
            .expect("create the ticker");
        lab.scheduler.lock().schedule(holder, 0);
        lab.scheduler.lock().schedule(ticker, 0);
        lab.run_until_idle();
        let futurelocks: Vec<_> = lab
            .check_invariants()
            .into_iter()
            .filter_map(|violation| match violation {
                InvariantViolation::Futurelock { task, held, .. } => Some((task, held.len())),
                _ => None,
            })
            .collect();
        assert_eq!(
            futurelocks,
            [(holder, 1)],
            "the fiber's obligation is held by its task, which the detector names"
        );
        release.send_blocking(()).expect("the fiber still waits");
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
    }

    // --- A cancellation polls the fiber again (br-asupersync-tc55xq) ---

    /// Waits as a semaphore or RwLock acquire does: it registers no cancel
    /// waker and sees cancellation only when it is polled again. It checks
    /// `waited_on`, or else the ambient context (the fiber's own).
    fn sees_cancel_only_when_polled(waited_on: Option<Cx>) -> impl Future<Output = CancelKind> {
        poll_fn(move |_| {
            let cx = waited_on
                .clone()
                .unwrap_or_else(|| Cx::current().expect("an ambient context"));
            if cx.checkpoint().is_err() {
                let reason = cx
                    .cancel_reason()
                    .expect("a cancelled context has a reason");
                Poll::Ready(reason.kind)
            } else {
                Poll::Pending
            }
        })
    }

    #[test]
    fn a_handle_cancel_polls_a_fiber_whose_wait_registered_no_cancel_waker() {
        let kind = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let wait = s.spawn(sees_cancel_only_when_polled(None));
                    crate::runtime::yield_now().await;
                    wait.cancel();
                    wait.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(kind, CancelKind::User);
    }

    #[test]
    fn cancelling_a_fiber_reaches_the_fibers_of_a_scope_nested_in_it() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let outer = s.spawn(async {
                        scope(|inner| async move {
                            inner.spawn(until_cancelled()).await.expect("inner fiber")
                        })
                        .await
                    });
                    crate::runtime::yield_now().await;
                    outer.cancel();
                    outer.await.expect("outer fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::User);
    }

    #[test]
    fn the_tasks_cancellation_polls_a_fiber_waiting_on_the_tasks_context() {
        let kind = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let wait = s.spawn(sees_cancel_only_when_polled(Some(task_ref.clone())));
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    wait.await.expect("fiber")
                })
                .await
            })
        });
        assert_eq!(kind, CancelKind::Shutdown);
    }

    // --- The task's cancellation is passed on once ---

    #[test]
    fn the_tasks_cancellation_is_passed_to_each_fiber_once() {
        let calls = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let fibers: Vec<_> = (0..3)
                        .map(|_| {
                            s.spawn(async {
                                let _ = until_cancelled().await;
                                // A cleanup that takes several polls.
                                for _ in 0..5 {
                                    crate::runtime::yield_now().await;
                                }
                            })
                        })
                        .collect();
                    crate::runtime::yield_now().await;
                    INHERIT_CALLS.with(|calls| calls.set(0));
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    for fiber in fibers {
                        fiber.await.expect("fiber");
                    }
                })
                .await;
                INHERIT_CALLS.with(Cell::get)
            })
        });
        assert_eq!(
            calls, 3,
            "one inherit per live fiber, not one per scope poll"
        );
    }

    #[test]
    fn a_fiber_started_after_the_task_was_cancelled_sees_the_cancellation() {
        let reason = within_watchdog(|| {
            let task_cx = Cx::for_testing();
            let task_ref = &task_cx;
            block_on_in(&task_cx, async {
                scope(|s| async move {
                    let first = s.spawn(until_cancelled());
                    crate::runtime::yield_now().await;
                    task_ref.cancel_with(CancelKind::Shutdown, Some("the task is cancelled"));
                    first.await.expect("first fiber");
                    // The cancellation has been passed to the live fibers
                    // already; a fiber started now still gets it.
                    s.spawn(until_cancelled()).await.expect("late fiber")
                })
                .await
            })
        });
        assert_eq!(reason.kind, CancelKind::Shutdown);
    }
