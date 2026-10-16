    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now::yield_now;
    use crate::types::{Budget, RegionId, TaskId};
    use futures_lite::future;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// A waiter at a full fallback cap is parked until a slot is released;
    /// it no longer wakes itself on every poll.
    #[test]
    fn a_full_fallback_cap_parks_the_waiter_until_a_slot_is_released() {
        init_test("a_full_fallback_cap_parks_the_waiter_until_a_slot_is_released");
        struct Flag(std::sync::atomic::AtomicBool);
        impl std::task::Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let count = AtomicUsize::new(0);
        let waiters = Mutex::new(VecDeque::new());
        let first = Context::from_waker(Waker::noop());
        assert!(poll_claim_fallback_slot(&count, 1, &waiters, &first).is_ready());

        let flag = Arc::new(Flag(std::sync::atomic::AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let waiting = Context::from_waker(&waker);
        assert!(poll_claim_fallback_slot(&count, 1, &waiters, &waiting).is_pending());
        assert!(
            !flag.0.load(Ordering::SeqCst),
            "a waiter at the cap is parked, not re-polled"
        );

        release_fallback_slot(&count, &waiters);
        assert!(
            flag.0.load(Ordering::SeqCst),
            "a released slot wakes the waiter"
        );
        assert!(poll_claim_fallback_slot(&count, 1, &waiters, &waiting).is_ready());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drained_cancelled_pool_envelope_retires_capture_before_publication() {
        struct Capture {
            drops: Arc<AtomicUsize>,
            was_finished_on_drop: Arc<std::sync::atomic::AtomicBool>,
            state: Arc<DrainedBlockingState<u8>>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                self.was_finished_on_drop.store(
                    self.state.inner.lock().finished,
                    Ordering::SeqCst,
                );
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let was_finished_on_drop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = DrainedBlockingState::new();
        let capture = Capture {
            drops: Arc::clone(&drops),
            was_finished_on_drop: Arc::clone(&was_finished_on_drop),
            state: Arc::clone(&state),
        };
        let called = Arc::clone(&calls);
        state.cancel(crate::types::CancelReason::user("cancelled before pool claim"));
        let envelope = DrainedPoolWork {
            work: Some(move || {
                called.fetch_add(1, Ordering::SeqCst);
                drop(capture);
                7_u8
            }),
            cx: Cx::for_testing(),
            state: Arc::clone(&state),
            result: None,
        };
        envelope.run();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            !was_finished_on_drop.load(Ordering::SeqCst),
            "captures must be dropped before completion is published to state"
        );
        let mut state = state.inner.lock();
        assert!(state.finished);
        assert!(matches!(state.result.take(),
            Some(Err(crate::runtime::JoinError::Cancelled(reason)))
                if reason.kind == crate::types::CancelKind::User));
    }

    #[test]
    fn drained_skipped_capture_panic_is_a_terminal_panic() {
        struct Panics;
        impl Drop for Panics {
            fn drop(&mut self) { panic!("drained capture retirement sentinel"); }
        }
        let state = DrainedBlockingState::<u8>::new();
        let capture = Panics;
        let envelope = DrainedPoolWork {
            work: Some(move || { drop(capture); 1_u8 }),
            cx: Cx::for_testing(),
            state: Arc::clone(&state),
            result: None,
        };
        // Mirrors the blocking pool dropping a skipped or rejected job.
        drop(envelope);
        let mut state = state.inner.lock();
        assert!(state.finished);
        assert!(matches!(state.result.take(),
            Some(Err(crate::runtime::JoinError::Panicked(payload)))
                if payload.message() == "drained capture retirement sentinel"));
    }

    #[test]
    fn drained_join_cannot_publish_a_late_result_after_observed_task_teardown() {
        let cx = Cx::for_testing();
        let (sender, task) = crate::runtime::task_handle::task_handle_channel::<()>(
            cx.task_id(), Arc::downgrade(&cx.inner),
        );
        let state = DrainedBlockingState::new();
        let mut handle = DrainedBlockingHandle::new(task, Arc::clone(&state));
        // Teardown closes the actual task's terminal publisher before the pool
        // finishes. The first observed terminal is final for this handle.
        drop(sender);
        assert!(matches!(future::block_on(handle.join()),
            Err(crate::runtime::JoinError::Cancelled(_))));
        state.finish(Ok(73_u8));
        assert!(matches!(future::block_on(handle.join()),
            Err(crate::runtime::JoinError::PolledAfterCompletion)));
        assert_eq!(state.inner.lock().result.take().unwrap().unwrap(), 73);
    }

    #[test]
    fn spawn_blocking_returns_result() {
        init_test("spawn_blocking_returns_result");
        future::block_on(async {
            let result = spawn_blocking(|| 42).await;
            crate::assert_with_log!(result == 42, "result", 42, result);
        });
        crate::test_complete!("spawn_blocking_returns_result");
    }

    #[test]
    fn spawn_blocking_io_returns_result() {
        init_test("spawn_blocking_io_returns_result");
        future::block_on(async {
            let result = spawn_blocking_io(|| Ok::<_, std::io::Error>(42))
                .await
                .unwrap();
            crate::assert_with_log!(result == 42, "result", 42, result);
        });
        crate::test_complete!("spawn_blocking_io_returns_result");
    }

    #[test]
    fn spawn_blocking_io_propagates_error() {
        init_test("spawn_blocking_io_propagates_error");
        future::block_on(async {
            let result: std::io::Result<()> = spawn_blocking_io(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test error",
                ))
            })
            .await;
            crate::assert_with_log!(result.is_err(), "is error", true, result.is_err());
        });
        crate::test_complete!("spawn_blocking_io_propagates_error");
    }

    /// The fallback thread's handle while it is parked, if it is.
    fn parked_fallback_thread(id: thread::ThreadId) -> Option<bool> {
        parked_thread(id)
    }

    /// Waits until a parked fallback thread has finished, then makes another
    /// fallback spawn and checks that it joined (and so un-parked) the thread.
    fn the_next_fallback_spawn_joins(id: thread::ThreadId) {
        let start = std::time::Instant::now();
        while parked_fallback_thread(id) == Some(false) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "worker never finished"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        future::block_on(spawn_blocking(|| ()));
        assert_eq!(
            parked_fallback_thread(id),
            None,
            "a finished parked thread was not joined"
        );
    }

    thread_local! {
        /// Set by a test closure on its fallback thread; dropped as that thread exits.
        static SLOW_EXIT: std::cell::RefCell<Option<SlowExit>> = const { std::cell::RefCell::new(None) };
    }

    /// Keeps a thread inside its exit for 200 ms, so the window in which a
    /// dropped `JoinHandle` would detach an exiting thread is easy to hit, then
    /// records that the thread's exit got that far.
    struct SlowExit(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for SlowExit {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_millis(200));
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// GitHub #80 (BZ19951): spawn_blocking's no-runtime fallback dropped its
    /// thread's JoinHandle when the result arrived, detaching a thread that was
    /// exiting at that moment, which can fault in pthread_detach on glibc before
    /// 2.43. Called as the reporter did (no asupersync context, a plain
    /// block_on), the worker spends 200 ms in its exit. When spawn_blocking
    /// returns it must have joined the thread (its exit completed) or parked
    /// its handle, never dropped it. `is_finished` turns true once the closure
    /// returns, before thread-local destructors run, so either is possible.
    #[test]
    fn the_fallback_thread_is_never_detached_while_it_exits() {
        init_test("the_fallback_thread_is_never_detached_while_it_exits");
        assert!(
            Cx::current().is_none(),
            "the fallback path needs no context"
        );
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = Arc::clone(&exited);
        let (value, worker) = future::block_on(spawn_blocking(move || {
            SLOW_EXIT.with(|slot| *slot.borrow_mut() = Some(SlowExit(marker)));
            (7, std::thread::current().id())
        }));
        assert_eq!(value, 7);
        let joined = exited.load(std::sync::atomic::Ordering::Acquire);
        let parked = parked_fallback_thread(worker).is_some();
        assert!(
            joined || parked,
            "the exiting fallback thread's handle was dropped (detached): neither joined nor parked"
        );
        if parked {
            the_next_fallback_spawn_joins(worker);
        }
        crate::test_complete!("the_fallback_thread_is_never_detached_while_it_exits");
    }

    /// The same for a waiter dropped before the result (soft cancellation): the
    /// closure keeps running and its thread is parked, not detached.
    #[test]
    fn a_dropped_fallback_waiter_parks_its_running_thread() {
        init_test("a_dropped_fallback_waiter_parks_its_running_thread");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut waiter = Box::pin(spawn_blocking(move || {
            started_tx.send(std::thread::current().id()).unwrap();
            let _ = release_rx.recv();
        }));
        assert!(future::block_on(future::poll_once(&mut waiter)).is_none());
        let worker = started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        drop(waiter);
        assert_eq!(
            parked_fallback_thread(worker),
            Some(false),
            "a dropped waiter's running thread was detached instead of parked"
        );
        release_tx.send(()).unwrap();
        the_next_fallback_spawn_joins(worker);
        crate::test_complete!("a_dropped_fallback_waiter_parks_its_running_thread");
    }

    #[test]
    fn spawn_blocking_captures_closure() {
        init_test("spawn_blocking_captures_closure");
        future::block_on(async {
            let counter = Arc::new(AtomicU32::new(0));
            let counter_clone = Arc::clone(&counter);

            spawn_blocking(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            })
            .await;

            let count = counter.load(Ordering::Relaxed);
            crate::assert_with_log!(count == 1, "counter incremented", 1u32, count);
        });
        crate::test_complete!("spawn_blocking_captures_closure");
    }

    #[test]
    fn spawn_blocking_uses_pool_when_current() {
        init_test("spawn_blocking_uses_pool_when_current");
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(cx.blocking_pool_handle().is_none());
        let cx = cx.with_blocking_pool_handle(Some(pool.handle()));
        let inherited = cx.blocking_pool_handle().expect("attached pool handle");
        let detached = cx.clone().with_blocking_pool_handle(None);
        assert!(detached.blocking_pool_handle().is_none());
        assert!(cx.blocking_pool_handle().is_some());

        {
            let _restricted = cx
                .restrict::<crate::cx::cap::None>()
                .set_current_restricted();
            // Ambient lookup retypes to All, so only the runtime mask prevents
            // a less-privileged caller from extracting submission authority.
            let ambient = Cx::current().expect("restricted ambient context");
            assert!(ambient.blocking_pool_handle().is_none());
        }
        assert!(cx.blocking_pool_handle().is_some());

        // The returned handle dispatches actual work through the same pool;
        // detaching a context clone must not detach or shut down its parent.
        let executed = Arc::new(AtomicU32::new(0));
        let executed_in_pool = Arc::clone(&executed);
        let task = inherited.spawn(move || {
            executed_in_pool.fetch_add(1, Ordering::Relaxed);
        });
        assert!(task.wait_timeout(std::time::Duration::from_secs(5)));
        assert_eq!(executed.load(Ordering::Relaxed), 1);

        let _guard = Cx::set_current(Some(cx));

        let thread_name = future::block_on(async {
            spawn_blocking(|| {
                std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_string()
            })
            .await
        });

        crate::assert_with_log!(
            thread_name.contains("-blocking-"),
            "thread name uses pool",
            true,
            thread_name.contains("-blocking-")
        );
        crate::test_complete!("spawn_blocking_uses_pool_when_current");
    }

    #[test]
    fn spawn_blocking_inline_when_no_pool() {
        init_test("spawn_blocking_inline_when_no_pool");
        let cx: Cx = Cx::for_testing();
        let _guard = Cx::set_current(Some(cx));
        let current_id = std::thread::current().id();

        let thread_id =
            future::block_on(async { spawn_blocking(|| std::thread::current().id()).await });

        crate::assert_with_log!(
            thread_id == current_id,
            "same thread",
            current_id,
            thread_id
        );
        crate::test_complete!("spawn_blocking_inline_when_no_pool");
    }

    #[test]
    fn spawn_blocking_preserves_restricted_context_pool_placement() {
        use std::future::Future;

        init_test("spawn_blocking_preserves_restricted_context_pool_placement");
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("native runtime");
        let pool = crate::runtime::BlockingPool::new(1, 1);
        runtime.block_on(async {
            let parent = Cx::current().expect("native parent context");
            let restricted = parent
                .clone()
                .with_blocking_pool_handle(Some(pool.handle()))
                .restrict::<crate::cx::cap::None>();
            let caller = std::thread::current().id();

            for attached in [true, false] {
                let installed = if attached {
                    restricted.clone()
                } else {
                    restricted.clone().with_blocking_pool_handle(None)
                };
                let expected_ambient = {
                    let _guard = installed.clone().set_current_restricted();
                    Cx::current().expect("ambient restriction").capabilities()
                };
                assert_eq!(
                    expected_ambient.effective,
                    restricted.capabilities().effective
                );
                let mut operation = std::pin::pin!(spawn_blocking(|| {
                    (
                        std::thread::current().id(),
                        Cx::current().map(|cx| cx.capabilities()),
                    )
                }));
                let (execution_thread, worker_capabilities) = std::future::poll_fn(|task| {
                    let guard = installed.clone().set_current_restricted();
                    let ambient = Cx::current().expect("restricted ambient context");
                    assert!(!ambient.capabilities().spawn);
                    assert!(ambient.blocking_pool_handle().is_none());
                    assert!(matches!(
                        ambient.spawn(|_| async {}),
                        Err(crate::runtime::SpawnError::RuntimeUnavailable)
                    ));
                    let result = operation.as_mut().poll(task);
                    assert_eq!(
                        Cx::current().expect("unchanged restriction").capabilities(),
                        ambient.capabilities()
                    );
                    drop(guard);
                    assert_eq!(
                        Cx::current().expect("restored parent").task_id(),
                        parent.task_id()
                    );
                    result
                })
                .await;

                if attached {
                    assert_ne!(execution_thread, caller, "use the assigned blocking pool");
                    assert!(
                        worker_capabilities.is_none(),
                        "do not fabricate a worker Cx"
                    );
                } else {
                    assert_eq!(execution_thread, caller, "detached contexts stay inline");
                    assert_eq!(worker_capabilities, Some(expected_ambient));
                }
                assert_eq!(
                    Cx::current()
                        .expect("native parent restored")
                        .capabilities(),
                    parent.capabilities()
                );
            }
        });
        pool.shutdown();
        crate::test_complete!("spawn_blocking_preserves_restricted_context_pool_placement");
    }

    #[test]
    fn spawn_blocking_falls_back_when_pool_rejects_submission() {
        init_test("spawn_blocking_falls_back_when_pool_rejects_submission");
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let handle = pool.handle();
        pool.shutdown();
        let caller = std::thread::current().id();

        let (value, execution_thread) = future::block_on(spawn_blocking_on_pool(handle, || {
            (42_u32, std::thread::current().id())
        }));

        assert_eq!(value, 42);
        assert_eq!(
            execution_thread, caller,
            "a shutdown-rejected blocking operation must use the documented inline fallback",
        );
        crate::test_complete!("spawn_blocking_falls_back_when_pool_rejects_submission");
    }

    #[test]
    fn spawn_blocking_runs_in_parallel() {
        init_test("spawn_blocking_runs_in_parallel");
        future::block_on(async {
            let counter = Arc::new(AtomicU32::new(0));

            let c1 = Arc::clone(&counter);
            let h1 = spawn_blocking(move || {
                thread::sleep(Duration::from_millis(10));
                c1.fetch_add(1, Ordering::Relaxed);
                1
            });

            let c2 = Arc::clone(&counter);
            let h2 = spawn_blocking(move || {
                thread::sleep(Duration::from_millis(10));
                c2.fetch_add(1, Ordering::Relaxed);
                2
            });

            // Since `spawn_blocking` is lazy, we must poll them concurrently
            // to actually run the background threads in parallel.
            let (r1, r2) = future::zip(h1, h2).await;

            let count = counter.load(Ordering::Relaxed);
            crate::assert_with_log!(count == 2, "both completed", 2u32, count);
            crate::assert_with_log!(r1 == 1, "first result", 1, r1);
            crate::assert_with_log!(r2 == 2, "second result", 2, r2);
        });
        crate::test_complete!("spawn_blocking_runs_in_parallel");
    }

    #[test]
    fn spawn_blocking_pool_overflow_queues_under_lab_runtime() {
        init_test("spawn_blocking_pool_overflow_queues_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0x5A0B_B10C)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let pool_handle = pool.handle();
        let checkpoints = Arc::new(StdMutex::new(Vec::<Value>::new()));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let first_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_started = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let (first_value, second_value, queued_before_release, second_started_after, checkpoints) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let first_spawn_cx = cx.clone();
                let second_spawn_cx = cx.clone();

                let first_task = LabRuntimeTarget::spawn(&first_spawn_cx, Budget::INFINITE, {
                    let pool_handle = pool_handle.clone();
                    let checkpoints = Arc::clone(&checkpoints);
                    let gate = Arc::clone(&gate);
                    let first_started = Arc::clone(&first_started);
                    async move {
                        spawn_blocking_on_pool(pool_handle, move || {
                            first_started.store(true, Ordering::SeqCst);
                            let started = serde_json::json!({
                                "phase": "first_started",
                            });
                            tracing::info!(event = %started, "spawn_blocking_lab_checkpoint");
                            checkpoints
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(started);

                            let (lock, cvar) = &*gate;
                            let mut released = lock
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            while !*released {
                                released = cvar
                                    .wait(released)
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                            }

                            let completed = serde_json::json!({
                                "phase": "first_completed",
                                "value": 11,
                            });
                            tracing::info!(event = %completed, "spawn_blocking_lab_checkpoint");
                            checkpoints
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(completed);
                            11
                        })
                        .await
                    }
                });

                while !first_started.load(Ordering::SeqCst) {
                    yield_now().await;
                }

                let second_task = LabRuntimeTarget::spawn(&second_spawn_cx, Budget::INFINITE, {
                    let pool_handle = pool_handle.clone();
                    let checkpoints = Arc::clone(&checkpoints);
                    let second_started = Arc::clone(&second_started);
                    async move {
                        spawn_blocking_on_pool(pool_handle, move || {
                            second_started.store(true, Ordering::SeqCst);
                            let started = serde_json::json!({
                                "phase": "second_started",
                            });
                            tracing::info!(event = %started, "spawn_blocking_lab_checkpoint");
                            checkpoints
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(started);
                            22
                        })
                        .await
                    }
                });

                yield_now().await;
                yield_now().await;

                let queued_before_release = !second_started.load(Ordering::SeqCst);
                let queued = serde_json::json!({
                    "phase": "queue_observed",
                    "second_started": second_started.load(Ordering::SeqCst),
                });
                tracing::info!(event = %queued, "spawn_blocking_lab_checkpoint");
                checkpoints
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(queued);

                {
                    let (lock, cvar) = &*gate;
                    let mut released = lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *released = true;
                    cvar.notify_all();
                }

                let first_outcome = first_task.await;
                crate::assert_with_log!(
                    matches!(first_outcome, crate::types::Outcome::Ok(11)),
                    "first blocking task completes successfully",
                    true,
                    matches!(first_outcome, crate::types::Outcome::Ok(11))
                );
                let crate::types::Outcome::Ok(first_value) = first_outcome else {
                    panic!("first blocking task should finish successfully");
                };

                let second_outcome = second_task.await;
                crate::assert_with_log!(
                    matches!(second_outcome, crate::types::Outcome::Ok(22)),
                    "second blocking task completes successfully",
                    true,
                    matches!(second_outcome, crate::types::Outcome::Ok(22))
                );
                let crate::types::Outcome::Ok(second_value) = second_outcome else {
                    panic!("second blocking task should finish successfully");
                };

                (
                    first_value,
                    second_value,
                    queued_before_release,
                    second_started.load(Ordering::SeqCst),
                    checkpoints
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                )
            });

        assert_eq!(first_value, 11);
        assert_eq!(second_value, 22);
        assert!(
            queued_before_release,
            "second blocking task should remain queued while the single worker is occupied"
        );
        assert!(
            second_started_after,
            "second blocking task should eventually start after the first releases the worker"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "first_started"),
            "first task start checkpoint should be recorded"
        );
        assert!(
            checkpoints.iter().any(|event| {
                event["phase"] == "queue_observed" && event["second_started"] == false
            }),
            "queue observation checkpoint should record that the second task was still queued"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "second_started"),
            "second task start checkpoint should be recorded"
        );

        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "spawn_blocking lab-runtime overflow test should leave runtime invariants clean: {violations:?}"
        );
        assert!(
            pool.shutdown_and_wait(Duration::from_secs(1)),
            "blocking pool should shut down cleanly after the test"
        );
    }

    #[test]
    fn blocking_oneshot_receiver_drop_retires_waker_after_unlock() {
        struct DropProbe {
            state: std::sync::Weak<Mutex<BlockingOneshotState<u32>>>,
            observed: Arc<Mutex<Vec<Option<bool>>>>,
        }

        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for DropProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                let detached = self
                    .state
                    .upgrade()
                    .and_then(|state| state.try_lock().map(|guard| guard.waker.is_none()));
                self.observed.lock().push(detached);
            }
        }

        init_test("blocking_oneshot_receiver_drop_retires_waker_after_unlock");
        let (tx, mut rx) = BlockingOneshot::<u32>::new();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let waker = Waker::from(Arc::new(DropProbe {
            state: Arc::downgrade(&tx.state),
            observed: Arc::clone(&observed),
        }));
        assert!(
            std::pin::Pin::new(&mut rx)
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        assert!(tx.state.lock().waker.is_some(), "waiter was registered");
        drop(waker);
        assert!(observed.lock().is_empty(), "receiver owns the last waker");

        drop(rx);

        assert_eq!(*observed.lock(), vec![Some(true)]);
        tx.send(Ok(42));
        crate::test_complete!("blocking_oneshot_receiver_drop_retires_waker_after_unlock");
    }

    #[test]
    fn blocking_oneshot_waker_replacement_can_complete_sender() {
        struct DropProbe {
            sender: Arc<Mutex<Option<BlockingOneshot<u32>>>>,
            state: std::sync::Weak<Mutex<BlockingOneshotState<u32>>>,
            unlocked: Arc<Mutex<Vec<bool>>>,
        }

        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for DropProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                let unlocked = self
                    .state
                    .upgrade()
                    .is_some_and(|state| state.try_lock().is_some());
                self.unlocked.lock().push(unlocked);
                // A failed try_lock records the old defect without hanging the
                // test. The external owner retains the sender in that case.
                if unlocked {
                    let sender = self.sender.lock().take();
                    if let Some(sender) = sender {
                        sender.send(Ok(42));
                    }
                }
            }
        }

        struct WakeCount(AtomicU32);

        impl std::task::Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        init_test("blocking_oneshot_waker_replacement_can_complete_sender");
        let (tx, mut rx) = BlockingOneshot::<u32>::new();
        let state = Arc::clone(&tx.state);
        let sender = Arc::new(Mutex::new(Some(tx)));
        let unlocked = Arc::new(Mutex::new(Vec::new()));
        let old_waker = Waker::from(Arc::new(DropProbe {
            sender: Arc::clone(&sender),
            state: Arc::downgrade(&state),
            unlocked: Arc::clone(&unlocked),
        }));
        assert!(
            std::pin::Pin::new(&mut rx)
                .poll(&mut std::task::Context::from_waker(&old_waker))
                .is_pending()
        );
        drop(old_waker);
        assert!(
            unlocked.lock().is_empty(),
            "receiver owns the last old waker"
        );

        let wakes = Arc::new(WakeCount(AtomicU32::new(0)));
        let new_waker = Waker::from(Arc::clone(&wakes));
        let mut context = std::task::Context::from_waker(&new_waker);
        assert!(std::pin::Pin::new(&mut rx).poll(&mut context).is_pending());

        assert_eq!(*unlocked.lock(), vec![true]);
        assert!(
            sender.lock().is_none(),
            "drop callback completed the sender"
        );
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1, "new waiter was woken");
        assert_eq!(
            std::pin::Pin::new(&mut rx).poll(&mut context),
            std::task::Poll::Ready(42)
        );
        assert!(state.lock().waker.is_none());
        crate::test_complete!("blocking_oneshot_waker_replacement_can_complete_sender");
    }

    #[test]
    fn blocking_oneshot_sender_drop_fails_closed() {
        init_test("blocking_oneshot_sender_drop_fails_closed");
        let (tx, rx) = BlockingOneshot::<u32>::new();
        drop(tx);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future::block_on(rx);
        }));

        let payload = panic.expect_err("receiver should fail closed when sender drops");
        let message = payload
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();

        crate::assert_with_log!(
            message.contains("without producing a result"),
            "receiver panic message",
            true,
            message.contains("without producing a result")
        );
        crate::test_complete!("blocking_oneshot_sender_drop_fails_closed");
    }

    #[test]
    fn blocking_oneshot_success_repoll_fails_closed() {
        init_test("blocking_oneshot_success_repoll_fails_closed");
        let (tx, rx) = BlockingOneshot::<u32>::new();
        tx.send(Ok(42));

        let mut rx = Box::pin(rx);
        let first = future::block_on(std::future::poll_fn(|cx| rx.as_mut().poll(cx)));
        crate::assert_with_log!(first == 42, "first result", 42u32, first);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future::block_on(std::future::poll_fn(|cx| rx.as_mut().poll(cx)));
        }));

        let payload = panic.expect_err("second poll should fail closed");
        let message = payload
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();

        crate::assert_with_log!(
            message.contains("polled after completion"),
            "repoll panic message",
            true,
            message.contains("polled after completion")
        );
        crate::test_complete!("blocking_oneshot_success_repoll_fails_closed");
    }

    #[test]
    fn blocking_oneshot_sender_drop_repoll_fails_closed() {
        init_test("blocking_oneshot_sender_drop_repoll_fails_closed");
        let (tx, rx) = BlockingOneshot::<u32>::new();
        drop(tx);

        let mut rx = Box::pin(rx);
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future::block_on(std::future::poll_fn(|cx| rx.as_mut().poll(cx)));
        }));
        let first_payload = first.expect_err("first poll should fail closed on sender drop");
        let first_message = first_payload
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| first_payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        crate::assert_with_log!(
            first_message.contains("without producing a result"),
            "first sender-drop panic message",
            true,
            first_message.contains("without producing a result")
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future::block_on(std::future::poll_fn(|cx| rx.as_mut().poll(cx)));
        }));
        let second_payload = second.expect_err("second poll should fail closed");
        let second_message = second_payload
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| second_payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        crate::assert_with_log!(
            second_message.contains("polled after completion"),
            "second sender-drop panic message",
            true,
            second_message.contains("polled after completion")
        );
        crate::test_complete!("blocking_oneshot_sender_drop_repoll_fails_closed");
    }

    #[test]
    #[should_panic(expected = "test panic")]
    fn spawn_blocking_propagates_panic() {
        future::block_on(async {
            spawn_blocking(|| std::panic::panic_any("test panic")).await;
        });
    }
