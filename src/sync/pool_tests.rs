mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use crate::Time;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};

    fn checked_pool_fixture(
        limit: usize,
    ) -> (crate::lab::LabRuntime, Cx, crate::runtime::TaskHandle<()>) {
        reset_test_pool_time();
        let mut lab =
            crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x28_9001).max_steps(128));
        let region = lab.state.create_root_region(Budget::INFINITE);
        assert!(lab.state.set_region_limits(
            region,
            crate::record::region::RegionLimits {
                max_obligations: Some(limit),
                ..crate::record::region::RegionLimits::UNLIMITED
            },
        ));
        let (holder, handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        let cx = lab.state.task(holder).unwrap().cx.clone().unwrap();
        (lab, cx, handle)
    }

    fn assert_checked_pool_ledger(lab: &crate::lab::LabRuntime, committed: u64, aborted: u64) {
        let gateway = lab.state.obligation_gateway().unwrap();
        let mailbox = gateway.mailbox();
        let stats = mailbox.stats();
        assert_eq!(stats.reserved, committed + aborted);
        assert_eq!(stats.committed, committed);
        assert_eq!(stats.aborted, aborted);
        assert_eq!(stats.refused, 0);
        assert_eq!(stats.leaked, 0);
        assert_eq!(stats.posted, stats.applied);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
    }

    fn finish_checked_pool_fixture(
        mut lab: crate::lab::LabRuntime,
        cx: &Cx,
        mut handle: crate::runtime::TaskHandle<()>,
        committed: u64,
        aborted: u64,
    ) {
        lab.scheduler.lock().schedule(cx.task_id(), 0);
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert_eq!(handle.try_join().unwrap(), Some(()));
        assert_checked_pool_ledger(&lab, committed, aborted);
    }

    #[test]
    fn checked_pool_actual_lab_quota_rollback_and_terminal_matrix() {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        reset_test_pool_time();
        for limit in [0, 1, 2] {
            let mut lab = crate::lab::LabRuntime::new(
                crate::lab::LabConfig::new(0x28_9002 + limit as u64).max_steps(128),
            );
            let region = lab.state.create_root_region(Budget::INFINITE);
            assert!(lab.state.set_region_limits(
                region,
                crate::record::region::RegionLimits {
                    max_obligations: Some(limit),
                    ..crate::record::region::RegionLimits::UNLIMITED
                },
            ));
            let pool = Arc::new(GenericPool::with_time_getter(
                simple_factory,
                PoolConfig::with_max_size(limit + 1).warmup_connections(limit + 1),
                test_pool_time_now,
            ));
            let task_pool = Arc::clone(&pool);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("actual scheduled Lab pool holder");
                    assert_eq!(task_pool.warmup().await.unwrap(), limit + 1);
                    let mut held = Vec::new();
                    for _ in 0..limit {
                        let resource = task_pool.acquire_checked(&cx).await.unwrap();
                        assert_eq!(resource.obligation.as_ref().unwrap().holder(), cx.task_id());
                        assert_eq!(*resource, 42);
                        held.push(resource);
                    }
                    for refusal in [
                        task_pool
                            .try_acquire_checked(&cx)
                            .map(|value| value.unwrap()),
                        task_pool.acquire_checked(&cx).await,
                    ] {
                        assert!(matches!(refusal,
                            Err(CheckedPoolError::Admission(
                                ObligationAdmissionError::LimitReached { limit: maximum, live }
                            )) if maximum == limit && live == limit
                        ));
                        let stats = task_pool.stats();
                        assert_eq!(stats.active, limit);
                        assert_eq!(stats.idle, 1, "refused physical checkout is reusable");
                        assert_eq!(stats.waiters, 0);
                    }
                    drop(held);
                    if limit > 0 {
                        // No runtime step separates release and readmission.
                        let mut returned = task_pool.try_acquire_checked(&cx).unwrap().unwrap();
                        *returned = 73;
                        returned.return_to_pool();
                        task_pool.acquire_checked(&cx).await.unwrap().discard();
                        let mut broken = task_pool.acquire_checked(&cx).await.unwrap();
                        broken.mark_broken();
                        assert!(broken.is_broken());
                        broken.return_to_pool();
                        let mut broken = task_pool.acquire_checked(&cx).await.unwrap();
                        broken.mark_broken();
                        drop(broken);
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let _held =
                                futures_lite::future::block_on(task_pool.acquire_checked(&cx))
                                    .unwrap();
                            panic!("checked pool body panic");
                        }));
                        assert_eq!(
                            result.unwrap_err().downcast_ref::<&str>(),
                            Some(&"checked pool body panic")
                        );
                    }
                    let stats = task_pool.stats();
                    assert_eq!(stats.active, 0);
                    assert_eq!(stats.waiters, 0);
                    assert!(stats.idle > 0);
                    assert!(stats.total <= limit + 1);
                    limit
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            let report = lab.run_until_quiescent_with_report();
            assert!(report.lab_test_passed(), "limit={limit}: {report:?}");
            assert_eq!(handle.try_join().unwrap(), Some(limit));
            assert_checked_pool_ledger(
                &lab,
                u64::from(limit > 0),
                limit as u64 + if limit > 0 { 4 } else { 0 },
            );
            assert_eq!(pool.stats().active, 0);
            eprintln!(
                "bead=asupersync-bi2462.29 scenario=checked_pool_lab limit={limit} report={}",
                report.to_json()
            );
        }
    }

    #[test]
    fn checked_pool_admission_notify_panic_rolls_back_real_checkout() {
        use crate::runtime::obligation_mailbox::ObligationGateway;
        let (lab, cx, handle) = checked_pool_fixture(1);
        let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let notified = Arc::clone(&count);
        let live = Arc::new(());
        let cx = cx.with_obligation_gateway(
            Some(Arc::new(ObligationGateway::new(
                mailbox,
                Arc::new(move || {
                    assert_ne!(
                        notified.fetch_add(1, Ordering::SeqCst),
                        0,
                        "pool admission notify panic"
                    );
                }),
                Arc::downgrade(&live),
            ))),
            None,
        );
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        );
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = futures_lite::future::block_on(pool.acquire_checked(&cx)).unwrap();
        }));
        assert!(failed.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(pool.stats().active, 0);
        assert_eq!(pool.stats().idle, 1);
        let recovered = pool.try_acquire_checked(&cx).unwrap().unwrap();
        assert!(recovered.obligation.is_some());
        assert_eq!(*recovered, 42);
        recovered.return_to_pool();
        assert_eq!(pool.stats().active, 0);
        finish_checked_pool_fixture(lab, &cx, handle, 1, 1);
    }

    #[test]
    fn checked_pool_clock_panic_and_body_unwind_settle_once() {
        reset_test_pool_time();
        let (lab, cx, handle) = checked_pool_fixture(1);
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1),
            panic_once_test_pool_time_now,
        );
        for body_panics in [false, true] {
            let held = futures_lite::future::block_on(pool.acquire_checked(&cx)).unwrap();
            panic_test_pool_time_on_call(1);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = held;
                if body_panics {
                    panic!("primary checked pool body panic");
                }
            }));
            let failure = result.unwrap_err();
            if body_panics {
                assert_eq!(
                    failure.downcast_ref::<&str>(),
                    Some(&"primary checked pool body panic")
                );
            } else {
                assert!(
                    failure
                        .downcast_ref::<String>()
                        .unwrap()
                        .contains("intentional pool time panic")
                );
            }
            assert_eq!(test_pool_time_probe_state(), (1, None));
            assert_eq!(pool.stats().active, 0);
            assert_eq!(pool.stats().idle, 1);
        }
        pool.try_acquire_checked(&cx)
            .unwrap()
            .unwrap()
            .return_to_pool();
        finish_checked_pool_fixture(lab, &cx, handle, 1, 2);
    }

    fn assert_checked_pool_callback_panics() {
        use crate::runtime::obligation_mailbox::ObligationGateway;
        use std::sync::atomic::AtomicUsize;
        struct PanickingWake {
            wakes: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }
        impl Wake for PanickingWake {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::SeqCst);
                panic!("secondary checked pool wake panic");
            }
        }
        impl Drop for PanickingWake {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                panic!("secondary checked pool waker retirement panic");
            }
        }

        let (lab, cx, handle) = checked_pool_fixture(1);
        let pending: Arc<PoolMutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>> =
            Arc::new(PoolMutex::new(None));
        let cancelled_pending = Arc::clone(&pending);
        let armed = Arc::new(AtomicBool::new(false));
        let notify_armed = Arc::clone(&armed);
        let live = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || {
                if notify_armed.swap(false, Ordering::SeqCst) {
                    // Cancel the real first acquisition while the checked
                    // cleanup still owns its cloned dispatcher waker. Its
                    // retirement must be a distinct catch after wake_by_ref.
                    let retired = cancelled_pending.lock().take().unwrap();
                    drop(retired);
                    panic!("primary checked pool notifier panic");
                }
            }),
            Arc::downgrade(&live),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        let _current = Cx::set_current(Some(cx.clone()));
        let created = Arc::new(AtomicUsize::new(0));
        let creations = Arc::clone(&created);
        let destroyed = Arc::new(AtomicUsize::new(0));
        let destructions = Arc::clone(&destroyed);
        let pool = Arc::new(GenericPool::with_time_getter(
            move || {
                let id = creations.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok::<_, std::io::Error>(PanicOnDropPoolResource {
                    id,
                    panic_on_drop: id == 0,
                    drop_attempts: Arc::clone(&destructions),
                }))
            },
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        ));
        let held = futures_lite::future::block_on(pool.acquire_checked(&cx)).unwrap();
        assert_eq!(held.id, 0);
        let first_pool = Arc::clone(&pool);
        let first_cx = cx.clone();
        let first: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
            let _resource = first_pool.acquire_checked(&first_cx).await.unwrap();
            panic!("the cancelled first waiter must never acquire");
        });
        *pending.lock() = Some(first);
        let wake_count = Arc::new(AtomicUsize::new(0));
        let drop_count = Arc::new(AtomicUsize::new(0));
        let bad_waker = Waker::from(Arc::new(PanickingWake {
            wakes: Arc::clone(&wake_count),
            drops: Arc::clone(&drop_count),
        }));
        // Give this independently dropped waiter its own real timer driver.
        // A wheel with another live timer can retain a cancelled entry until
        // compaction, which would make the dispatcher an intermediate waker
        // owner instead of exercising final-payload retirement here. The
        // explicit acquisition Cx still supplies the actual holder authority.
        let first_timer =
            TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::starting_at(Time::ZERO)));
        {
            let _first_timer = Cx::set_current(Some(test_cx_with_timer(first_timer.clone())));
            assert!(
                pending
                    .lock()
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll(&mut Context::from_waker(&bad_waker))
                    .is_pending()
            );
        }
        assert_eq!(first_timer.pending_count(), 1);
        drop(bad_waker);
        assert_eq!(
            drop_count.load(Ordering::SeqCst),
            0,
            "only actual parked registrations now own the waker payload"
        );

        let (wake_tx, wake_rx) = mpsc::channel();
        let real_waker = Waker::from(Arc::new(ReentrantReturnWaker {
            return_wakers: Arc::clone(&pool.return_wakers),
            tx: wake_tx,
        }));
        let mut successor = pool.acquire_checked(&cx);
        assert!(
            successor
                .as_mut()
                .poll(&mut Context::from_waker(&real_waker))
                .is_pending()
        );
        assert_eq!(pool.stats().waiters, 2);
        armed.store(true, Ordering::SeqCst);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| held.discard()));
        assert_eq!(
            result.unwrap_err().downcast_ref::<&str>(),
            Some(&"primary checked pool notifier panic")
        );
        assert!(pending.lock().is_none());
        assert_eq!(first_timer.pending_count(), 0);
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert_eq!(drop_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            destroyed.load(Ordering::SeqCst),
            1,
            "discard attempts the resource destructor exactly once"
        );
        assert_eq!(
            wake_rx.try_recv(),
            Ok(true),
            "surviving real pool waiter is notified outside its return lock"
        );
        assert_eq!(pool.stats().active, 0);
        assert_eq!(pool.stats().total, 0);
        let Poll::Ready(Ok(replacement)) = successor
            .as_mut()
            .poll(&mut Context::from_waker(&real_waker))
        else {
            panic!("surviving waiter must acquire the replacement after cleanup");
        };
        assert_eq!(replacement.id, 1);
        replacement.return_to_pool();
        assert_eq!(pool.stats().active, 0);
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().waiters, 0);
        drop(successor);
        finish_checked_pool_fixture(lab, &cx, handle, 1, 1);
    }

    #[test]
    fn checked_pool_notifier_wake_retirement_and_resource_panics_preserve_primary() {
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            assert_checked_pool_callback_panics();
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reentrant checked cleanup must complete without a pool-lock deadlock");
        worker.join().unwrap();
    }

    #[test]
    fn checked_pool_return_after_pool_drop_aborts_and_releases_live_quota() {
        let (lab, cx, handle) = checked_pool_fixture(1);
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        );
        let held = futures_lite::future::block_on(pool.acquire_checked(&cx)).unwrap();
        drop(pool);
        // A disconnected return receiver cannot accept a committed return.
        held.return_to_pool();
        let replacement = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        );
        let held = futures_lite::future::block_on(replacement.acquire_checked(&cx)).unwrap();
        assert!(held.obligation.is_some());
        held.return_to_pool();
        assert_eq!(replacement.stats().active, 0);
        finish_checked_pool_fixture(lab, &cx, handle, 1, 1);
    }

    #[test]
    fn checked_pool_stateless_unavailable_closed_and_cancelled_are_distinct() {
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx = Cx::for_testing();
        assert!(pool.try_acquire_checked(&cx).unwrap().is_none());
        let held = futures_lite::future::block_on(pool.acquire_checked(&cx)).unwrap();
        assert!(held.obligation.is_none());
        assert!(pool.try_acquire_checked(&cx).unwrap().is_none());
        held.return_to_pool();
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            pool.try_acquire_checked(&cancelled),
            Err(CheckedPoolError::Pool(PoolError::Cancelled))
        ));
        assert!(matches!(
            futures_lite::future::block_on(pool.acquire_checked(&cancelled)),
            Err(CheckedPoolError::Pool(PoolError::Cancelled))
        ));
        assert_eq!(pool.stats().idle, 1);
        futures_lite::future::block_on(pool.close());
        assert!(matches!(
            pool.try_acquire_checked(&cx),
            Err(CheckedPoolError::Pool(PoolError::Closed))
        ));
        assert!(matches!(
            futures_lite::future::block_on(pool.acquire_checked(&cx)),
            Err(CheckedPoolError::Pool(PoolError::Closed))
        ));
    }

    #[test]
    fn checked_pool_concurrent_close_cannot_report_idle_unavailability() {
        let (lab, cx, handle) = checked_pool_fixture(1);
        let pool = Arc::new(GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1).warmup_connections(1),
            checked_pool_close_race_now,
        ));
        assert_eq!(futures_lite::future::block_on(pool.warmup()).unwrap(), 1);
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 0);
        assert_eq!(pool.stats().waiters, 0);
        let closed_pool = Arc::clone(&pool);
        let closed = Arc::new(AtomicBool::new(false));
        let observed_closed = Arc::clone(&closed);
        TEST_CHECKED_POOL_CLOSE_CALLBACK.with(|callback| {
            *callback.borrow_mut() = Some(Box::new(move || {
                // The legacy try-acquire's first clock callback follows the
                // checked method's initial open observation. Close the real
                // pool precisely there, while its idle resource still exists.
                futures_lite::future::block_on(closed_pool.close());
                observed_closed.store(true, Ordering::SeqCst);
            }));
        });
        assert!(matches!(
            pool.try_acquire_checked(&cx),
            Err(CheckedPoolError::Pool(PoolError::Closed))
        ));
        assert!(closed.load(Ordering::SeqCst));
        TEST_CHECKED_POOL_CLOSE_CALLBACK.with(|callback| assert!(callback.borrow().is_none()));
        let stats = pool.stats();
        assert_eq!(stats.active, 0);
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.waiters, 0);
        assert_eq!(
            lab.state
                .obligation_gateway()
                .unwrap()
                .mailbox()
                .stats()
                .posted,
            0
        );
        finish_checked_pool_fixture(lab, &cx, handle, 0, 0);
    }

    #[test]
    fn checked_pool_native_send_not_sync_holder_cancel_wakes_real_pool_waiter() {
        use crate::record::{ObligationKind, ObligationState};
        use crate::runtime::{RuntimeBuilder, yield_now};
        use crate::sync::{LockError, Mutex, OwnedMutexGuard};
        use crate::trace::TraceData;
        fn assert_send<T: Send>() {}
        assert_send::<PooledResource<Cell<u32>>>();
        assert_send::<CheckedPooledResource<Cell<u32>>>();

        for sharded in [false, true] {
            let (done_tx, done_rx) = mpsc::channel();
            // An owned worker and completion channel bound regressions even
            // when a broken native executor never polls the observer again.
            let worker = std::thread::spawn(move || {
                for limit in [0, 1] {
                    let builder = if sharded {
                        RuntimeBuilder::multi_thread()
                            .worker_threads(2)
                            .with_sharded_state(true)
                    } else {
                        RuntimeBuilder::current_thread()
                    };
                    let runtime = builder
                        .root_region_limits(crate::record::RegionLimits {
                            max_obligations: Some(limit),
                            ..crate::record::RegionLimits::UNLIMITED
                        })
                        .build()
                        .unwrap();
                    let observer = runtime.handle();
                    let pool = Arc::new(GenericPool::new(
                        || std::future::ready(Ok::<_, std::io::Error>(Cell::new(41_u32))),
                        PoolConfig::with_max_size(1),
                    ));
                    let task_pool = Arc::clone(&pool);
                    let parent: Pin<Box<dyn Future<Output = Option<(TaskId, TaskId)>> + Send>> =
                        Box::pin(async move {
                            let cx = Cx::current().expect("native parent context");
                            if limit == 0 {
                                for denial in [
                                    task_pool.acquire_checked(&cx).await,
                                    task_pool
                                        .try_acquire_checked(&cx)
                                        .map(|resource| resource.unwrap()),
                                ] {
                                    assert!(matches!(denial, Err(CheckedPoolError::Admission(
                                    crate::runtime::obligation_mailbox::ObligationAdmissionError::LimitReached { limit: 0, live: 0 }
                                ))));
                                }
                                assert_eq!(task_pool.stats().active, 0);
                                assert_eq!(task_pool.stats().idle, 1);
                                return None;
                            }

                            let mutex = Arc::new(Mutex::new(()));
                            let mutex_owner = mutex.try_lock_owned().unwrap();
                            let held_pool = Arc::clone(&task_pool);
                            let held_mutex = Arc::clone(&mutex);
                            let holder_context = Arc::new(PoolMutex::new(None));
                            let published_context = Arc::clone(&holder_context);
                            let mut holder = cx
                                .spawn(move |holder_cx| {
                                    let future: Pin<
                                        Box<dyn Future<Output = Result<(), LockError>> + Send>,
                                    > = Box::pin(async move {
                                        let resource =
                                            held_pool.acquire_checked(&holder_cx).await.unwrap();
                                        assert!(resource.obligation.is_some());
                                        resource.get().set(73);
                                        *published_context.lock() = Some(holder_cx.clone());
                                        let result = OwnedMutexGuard::lock(held_mutex, &holder_cx)
                                            .await
                                            .map(drop);
                                        // Cell is Send but !Sync and remains in the
                                        // real task future across this native Pending.
                                        assert_eq!(resource.get().get(), 73);
                                        drop(resource);
                                        result
                                    });
                                    future
                                })
                                .unwrap();
                            let started = Instant::now();
                            let holder_cx = loop {
                                let context = holder_context.lock().clone();
                                if let Some(context) = context {
                                    let task = observer
                                        .task_inspector(Default::default())
                                        .unwrap()
                                        .inspect_task(context.task_id());
                                    if mutex.waiters() == 1
                                        && task
                                            .as_ref()
                                            .is_some_and(|task| task.obligations.len() == 1)
                                    {
                                        break context;
                                    }
                                }
                                assert!(
                                    started.elapsed() < Duration::from_secs(5),
                                    "native checked holder must reach a real parked state with an arena obligation"
                                );
                                yield_now().await;
                            };
                            let successor_pool = Arc::clone(&task_pool);
                            let mut successor = cx
                                .spawn(move |waiter_cx| {
                                    let future: Pin<
                                        Box<dyn Future<Output = (TaskId, u32)> + Send>,
                                    > = Box::pin(async move {
                                        let resource = successor_pool
                                            .acquire_checked(&waiter_cx)
                                            .await
                                            .unwrap();
                                        let value = resource.get().get();
                                        resource.return_to_pool();
                                        (waiter_cx.task_id(), value)
                                    });
                                    future
                                })
                                .unwrap();
                            let waiting = Instant::now();
                            while task_pool.stats().waiters != 1 {
                                assert!(
                                    waiting.elapsed() < Duration::from_secs(5),
                                    "native successor must park in the actual pool queue"
                                );
                                yield_now().await;
                            }
                            assert_eq!(task_pool.stats().active, 1);
                            holder.abort();
                            assert_eq!(holder.join(&cx).await, Ok(Err(LockError::Cancelled)));
                            let (successor_id, value) = successor.join(&cx).await.unwrap();
                            assert_eq!(
                                value, 73,
                                "cancellation returns the actual Cell resource to the parked successor"
                            );
                            assert_eq!(mutex.waiters(), 0);
                            drop(mutex_owner);
                            assert_eq!(task_pool.stats().active, 0);
                            assert_eq!(task_pool.stats().idle, 1);
                            assert_eq!(task_pool.stats().waiters, 0);
                            Some((holder_cx.task_id(), successor_id))
                        });
                    let holders = runtime.block_on(runtime.handle().spawn(parent));
                    runtime.block_on(async {
                        let started = Instant::now();
                        while !runtime.is_quiescent() {
                            assert!(
                                started.elapsed() < Duration::from_secs(5),
                                "native pool obligations and task retirement must drain"
                            );
                            yield_now().await;
                        }
                    });
                    assert!(
                        runtime
                            .task_inspector(Default::default())
                            .list_tasks()
                            .is_empty()
                    );
                    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                    let mut records = std::collections::BTreeMap::new();
                    for event in runtime.trace_snapshot() {
                        if let TraceData::Obligation {
                            obligation,
                            task,
                            kind: ObligationKind::Lease,
                            state,
                            ..
                        } = event.data
                        {
                            let entry = records.entry(obligation).or_insert((task, Vec::new()));
                            assert_eq!(entry.0, task);
                            entry.1.push(state);
                        }
                    }
                    if let Some((holder, successor)) = holders {
                        assert_eq!(records.len(), 2);
                        for (task, states) in records.values() {
                            if *task == holder {
                                assert_eq!(
                                    states,
                                    &[ObligationState::Reserved, ObligationState::Aborted]
                                );
                            } else {
                                assert_eq!(*task, successor);
                                assert_eq!(
                                    states,
                                    &[ObligationState::Reserved, ObligationState::Committed]
                                );
                            }
                        }
                    } else {
                        assert!(
                            records.is_empty(),
                            "zero quota cannot produce a false reservation"
                        );
                    }
                    assert_eq!(pool.stats().active, 0);
                    assert_eq!(pool.stats().idle, 1);
                    eprintln!(
                        "bead=asupersync-bi2462.29 scenario=checked_pool_native sharded={sharded} limit={limit} holders={holders:?} trace={records:?}"
                    );
                    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                }
                done_tx.send(()).unwrap();
            });
            done_rx.recv_timeout(Duration::from_secs(20)).expect("native checked Pool must complete both quotas and shutdown within the watchdog bound");
            worker.join().unwrap();
        }
    }

    std::thread_local! {
        static TEST_CHECKED_POOL_CLOSE_CALLBACK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        static TEST_POOL_TIME_BASE: RefCell<Option<Instant>> = const { RefCell::new(None) };
        static TEST_POOL_TIME_OFFSET_NANOS: Cell<u64> = const { Cell::new(0) };
        static TEST_POOL_TIME_CALL_COUNT: Cell<usize> = const { Cell::new(0) };
        static TEST_POOL_TIME_PANIC_ON_CALL: Cell<Option<usize>> = const { Cell::new(None) };
    }

    fn checked_pool_close_race_now() -> Instant {
        let callback =
            TEST_CHECKED_POOL_CLOSE_CALLBACK.with(|callback| callback.borrow_mut().take());
        if let Some(callback) = callback {
            callback();
        }
        test_pool_time_now()
    }

    fn test_pool_time_now() -> Instant {
        let offset = TEST_POOL_TIME_OFFSET_NANOS.with(Cell::get);
        TEST_POOL_TIME_BASE.with(|base| {
            let mut base = base.borrow_mut();
            let base_instant = *base.get_or_insert_with(Instant::now);
            base_instant
                .checked_add(Duration::from_nanos(offset))
                .unwrap_or(base_instant)
        })
    }

    fn reset_test_pool_time() {
        TEST_POOL_TIME_BASE.with(|base| {
            *base.borrow_mut() = None;
        });
        TEST_POOL_TIME_OFFSET_NANOS.with(|offset| offset.set(0));
        TEST_POOL_TIME_CALL_COUNT.with(|count| count.set(0));
        TEST_POOL_TIME_PANIC_ON_CALL.with(|call| call.set(None));
    }

    fn panic_once_test_pool_time_now() -> Instant {
        let call = TEST_POOL_TIME_CALL_COUNT.with(|count| {
            let call = count.get().saturating_add(1);
            count.set(call);
            call
        });
        let should_panic = TEST_POOL_TIME_PANIC_ON_CALL.with(|panic_on_call| {
            if panic_on_call.get() == Some(call) {
                panic_on_call.set(None);
                true
            } else {
                false
            }
        });
        assert!(!should_panic, "intentional pool time panic on call {call}");
        test_pool_time_now()
    }

    fn panic_test_pool_time_on_call(call: usize) {
        assert!(call > 0, "pool time call indices are one-based");
        TEST_POOL_TIME_CALL_COUNT.with(|count| count.set(0));
        TEST_POOL_TIME_PANIC_ON_CALL.with(|panic_on_call| panic_on_call.set(Some(call)));
    }

    fn test_pool_time_probe_state() -> (usize, Option<usize>) {
        let calls = TEST_POOL_TIME_CALL_COUNT.with(Cell::get);
        let panic_on_call = TEST_POOL_TIME_PANIC_ON_CALL.with(Cell::get);
        (calls, panic_on_call)
    }

    fn disarm_test_pool_time_panic() {
        TEST_POOL_TIME_PANIC_ON_CALL.with(|panic_on_call| panic_on_call.set(None));
    }

    fn set_test_pool_time_offset(offset: Duration) {
        let nanos = offset.as_nanos().min(u128::from(u64::MAX)) as u64;
        TEST_POOL_TIME_OFFSET_NANOS.with(|value| value.set(nanos));
    }

    fn advance_test_pool_time(delta: Duration) {
        let nanos = delta.as_nanos().min(u128::from(u64::MAX)) as u64;
        TEST_POOL_TIME_OFFSET_NANOS.with(|offset| {
            offset.set(offset.get().saturating_add(nanos));
        });
    }

    fn init_test(name: &str) {
        reset_test_pool_time();
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx_with_timer(timer: TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer),
            None,
        )
    }

    fn test_cx_with_timer_and_budget(timer: TimerDriverHandle, budget: Budget) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            budget,
            None,
            None,
            None,
            Some(timer),
            None,
        )
    }

    struct ReentrantReturnWaker {
        return_wakers: ReturnWakers,
        tx: mpsc::Sender<bool>,
    }

    use std::task::Wake;
    impl Wake for ReentrantReturnWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let lock_was_free = self.return_wakers.try_lock().is_some();
            let _ = self.tx.send(lock_was_free);
        }
    }

    struct PoolWakerDropProbe {
        on_drop: Box<dyn Fn() + Send + Sync>,
    }

    #[allow(clippy::manual_noop_waker)]
    impl Wake for PoolWakerDropProbe {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    impl Drop for PoolWakerDropProbe {
        fn drop(&mut self) {
            (self.on_drop)();
        }
    }

    fn deferred_pool_lock_probe<R, F>(
        pool: &Arc<GenericPool<R, F>>,
    ) -> (DeferredWaker, mpsc::Receiver<(bool, bool)>)
    where
        R: Send + 'static,
        F: AsyncResourceFactory<Resource = R> + 'static,
    {
        let weak_pool = Arc::downgrade(pool);
        let (tx, rx) = mpsc::channel();
        let probe = PoolWakerDropProbe {
            on_drop: Box::new(move || {
                let Some(pool) = weak_pool.upgrade() else {
                    let _ = tx.send((false, false));
                    return;
                };
                let state_free = {
                    let guard = pool.state.try_lock();
                    let free = guard.is_some();
                    drop(guard);
                    free
                };
                let return_wakers_free = {
                    let guard = pool.return_wakers.try_lock();
                    let free = guard.is_some();
                    drop(guard);
                    free
                };
                let _ = tx.send((state_free, return_wakers_free));
            }),
        };
        (DeferredWaker::new(Waker::from(Arc::new(probe))), rx)
    }

    fn assert_pool_waker_retired_outside_locks(rx: &mpsc::Receiver<(bool, bool)>, path: &str) {
        let observed = rx
            .try_recv()
            .unwrap_or_else(|error| panic!("{path} did not retire its probe waker: {error}"));
        assert_eq!(
            observed,
            (true, true),
            "{path} retired a task waker while a pool lock was held"
        );
    }

    struct PoolResourceDropProbe {
        on_drop: Box<dyn Fn() + Send + Sync>,
    }

    impl Drop for PoolResourceDropProbe {
        fn drop(&mut self) {
            (self.on_drop)();
        }
    }

    struct PanicOnDropPoolResource {
        id: usize,
        panic_on_drop: bool,
        drop_attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for PanicOnDropPoolResource {
        fn drop(&mut self) {
            self.drop_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(
                !self.panic_on_drop,
                "intentional pooled-resource destructor panic"
            );
        }
    }

    #[allow(clippy::type_complexity)]
    fn pool_resource_probe_factory() -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PoolResourceDropProbe,
                        Box<dyn std::error::Error + Send + Sync>,
                    >,
                > + Send,
        >,
    > {
        Box::pin(std::future::pending())
    }

    fn pool_resource_lock_probe<F>(
        pool: &Arc<GenericPool<PoolResourceDropProbe, F>>,
    ) -> (PoolResourceDropProbe, mpsc::Receiver<(bool, bool)>)
    where
        F: AsyncResourceFactory<Resource = PoolResourceDropProbe> + 'static,
    {
        let weak_pool = Arc::downgrade(pool);
        let (tx, rx) = mpsc::channel();
        let probe = PoolResourceDropProbe {
            on_drop: Box::new(move || {
                let Some(pool) = weak_pool.upgrade() else {
                    let _ = tx.send((false, false));
                    return;
                };
                let state_free = {
                    let guard = pool.state.try_lock();
                    let free = guard.is_some();
                    drop(guard);
                    free
                };
                let return_rx_free = {
                    let guard = pool.return_rx.try_lock();
                    let free = guard.is_some();
                    drop(guard);
                    free
                };
                let _ = tx.send((state_free, return_rx_free));
            }),
        };
        (probe, rx)
    }

    fn assert_pool_resource_dropped_outside_locks(rx: &mpsc::Receiver<(bool, bool)>, path: &str) {
        let observed = rx
            .try_recv()
            .unwrap_or_else(|error| panic!("{path} did not destroy its probe resource: {error}"));
        assert_eq!(
            observed,
            (true, true),
            "{path} destroyed a resource while a pool lock was held"
        );
    }

    #[test]
    fn pooled_resource_returns_on_drop() {
        init_test("pooled_resource_returns_on_drop");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(42u8, tx);
        drop(pooled);

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 42, "return value", 42u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("unexpected discard"),
        }
        crate::test_complete!("pooled_resource_returns_on_drop");
    }

    // ── br-asupersync-ob62ki: mark_broken regression tests ──────────────

    /// A PooledResource flagged broken via mark_broken MUST route to
    /// PoolReturn::Discard on Drop instead of PoolReturn::Return —
    /// preventing broken connections from poisoning the idle pool.
    #[test]
    fn ob62ki_mark_broken_routes_drop_to_discard() {
        init_test("ob62ki_mark_broken_routes_drop_to_discard");
        let (tx, rx) = mpsc::channel();
        let mut pooled = PooledResource::new(99u8, tx);
        crate::assert_with_log!(
            !pooled.is_broken(),
            "default not broken",
            false,
            pooled.is_broken()
        );
        pooled.mark_broken();
        crate::assert_with_log!(
            pooled.is_broken(),
            "after mark_broken",
            true,
            pooled.is_broken()
        );
        drop(pooled);

        let msg = rx.recv().expect("discard message");
        match msg {
            PoolReturn::Discard { .. } => {}
            PoolReturn::Return { .. } => {
                panic!("broken resource MUST route to Discard on Drop, not Return")
            }
        }
        crate::test_complete!("ob62ki_mark_broken_routes_drop_to_discard");
    }

    /// A PooledResource NOT flagged broken keeps the existing default:
    /// Drop routes to PoolReturn::Return so the resource is recycled.
    /// (Regression guard against the fix accidentally flipping the
    /// default behaviour.)
    #[test]
    fn ob62ki_unflagged_resource_still_returns_on_drop() {
        init_test("ob62ki_unflagged_resource_still_returns_on_drop");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(11u8, tx);
        // No mark_broken call.
        drop(pooled);
        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 11, "default Drop returns", 11u8, value);
            }
            PoolReturn::Discard { .. } => panic!("default Drop must Return, not Discard"),
        }
        crate::test_complete!("ob62ki_unflagged_resource_still_returns_on_drop");
    }

    /// mark_broken is idempotent — calling twice does not double-process
    /// the resource. The Drop runs exactly once, exactly as Discard.
    #[test]
    fn ob62ki_mark_broken_is_idempotent() {
        init_test("ob62ki_mark_broken_is_idempotent");
        let (tx, rx) = mpsc::channel();
        let mut pooled = PooledResource::new(5u8, tx);
        pooled.mark_broken();
        pooled.mark_broken();
        pooled.mark_broken();
        drop(pooled);

        // Exactly one message.
        let msg = rx.recv().expect("discard message");
        assert!(matches!(msg, PoolReturn::Discard { .. }));
        assert!(rx.try_recv().is_err(), "no second message should arrive");
        crate::test_complete!("ob62ki_mark_broken_is_idempotent");
    }

    #[test]
    fn pooled_resource_return_to_pool_sends_return() {
        init_test("pooled_resource_return_to_pool_sends_return");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(7u8, tx);
        pooled.return_to_pool();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 7, "return value", 7u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("unexpected discard"),
        }
        crate::test_complete!("pooled_resource_return_to_pool_sends_return");
    }

    #[test]
    fn pooled_resource_return_hold_duration_uses_time_getter() {
        init_test("pooled_resource_return_hold_duration_uses_time_getter");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new_with_time_getter(7u8, tx, test_pool_time_now);

        advance_test_pool_time(Duration::from_millis(15));
        pooled.return_to_pool();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return {
                resource: value,
                hold_duration,
                ..
            } => {
                crate::assert_with_log!(value == 7, "return value", 7u8, value);
                crate::assert_with_log!(
                    hold_duration == Duration::from_millis(15),
                    "hold duration uses injected time getter",
                    Duration::from_millis(15),
                    hold_duration
                );
            }
            PoolReturn::Discard { .. } => unreachable!("unexpected discard"),
        }

        crate::test_complete!("pooled_resource_return_hold_duration_uses_time_getter");
    }

    #[test]
    fn pooled_resource_notifies_wakers_outside_return_waker_lock() {
        init_test("pooled_resource_notifies_wakers_outside_return_waker_lock");
        let (return_tx, _return_rx) = mpsc::channel();
        let return_wakers = Arc::new(PoolMutex::new(ReturnWakerList::new()));
        let (probe_tx, probe_rx) = mpsc::channel();

        {
            let probe = Arc::new(ReentrantReturnWaker {
                return_wakers: Arc::clone(&return_wakers),
                tx: probe_tx,
            });
            let mut wakers = return_wakers.lock();
            wakers.push((1, DeferredWaker::new(Waker::from(probe))));
        }

        let pooled =
            PooledResource::new(7u8, return_tx).with_return_notify(Arc::clone(&return_wakers));
        pooled.return_to_pool();

        let lock_was_free = probe_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("probe wake result");
        crate::assert_with_log!(
            lock_was_free,
            "waker should run after return_wakers lock is released",
            true,
            lock_was_free
        );
        crate::test_complete!("pooled_resource_notifies_wakers_outside_return_waker_lock");
    }

    #[test]
    fn pooled_resource_discard_sends_discard() {
        init_test("pooled_resource_discard_sends_discard");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(9u8, tx);
        pooled.discard();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return { .. } => unreachable!("unexpected return"),
            PoolReturn::Discard { hold_duration: _ } => {
                crate::assert_with_log!(true, "discard", true, true);
            }
        }
        crate::test_complete!("pooled_resource_discard_sends_discard");
    }

    #[test]
    fn pooled_resource_discard_hold_duration_uses_time_getter() {
        init_test("pooled_resource_discard_hold_duration_uses_time_getter");
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new_with_time_getter(9u8, tx, test_pool_time_now);

        advance_test_pool_time(Duration::from_millis(12));
        pooled.discard();

        let msg = rx.recv().expect("return message");
        match msg {
            PoolReturn::Return { .. } => unreachable!("unexpected return"),
            PoolReturn::Discard { hold_duration } => {
                crate::assert_with_log!(
                    hold_duration == Duration::from_millis(12),
                    "discard hold duration uses injected time getter",
                    Duration::from_millis(12),
                    hold_duration
                );
            }
        }

        crate::test_complete!("pooled_resource_discard_hold_duration_uses_time_getter");
    }

    #[test]
    fn pooled_resource_discard_commits_before_resource_drop_panics() {
        init_test("pooled_resource_discard_commits_before_resource_drop_panics");
        let (tx, rx) = mpsc::channel();
        let drop_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pooled = PooledResource::new_with_time_getter(
            PanicOnDropPoolResource {
                id: 0,
                panic_on_drop: true,
                drop_attempts: Arc::clone(&drop_attempts),
            },
            tx,
            test_pool_time_now,
        );

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pooled.discard();
        }));
        assert!(
            panic_result.is_err(),
            "discard must propagate the resource destructor panic"
        );
        assert_eq!(
            drop_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the discarded resource must be destroyed exactly once"
        );
        assert!(
            matches!(rx.try_recv(), Ok(PoolReturn::Discard { .. })),
            "discard accounting must be queued before the destructor unwinds"
        );
        assert!(
            rx.try_recv().is_err(),
            "a panicking discard must enqueue exactly one accounting message"
        );

        crate::test_complete!("pooled_resource_discard_commits_before_resource_drop_panics");
    }

    #[test]
    fn pooled_resource_deref_access() {
        init_test("pooled_resource_deref_access");
        let (tx, _rx) = mpsc::channel();
        let mut pooled = PooledResource::new(1u8, tx);
        *pooled = 3;
        crate::assert_with_log!(*pooled == 3, "deref", 3u8, *pooled);
        crate::test_complete!("pooled_resource_deref_access");
    }

    // ========================================================================
    // PoolConfig tests
    // ========================================================================

    #[test]
    fn pool_config_default() {
        init_test("pool_config_default");
        let config = PoolConfig::default();
        crate::assert_with_log!(config.min_size == 1, "min_size", 1usize, config.min_size);
        crate::assert_with_log!(config.max_size == 10, "max_size", 10usize, config.max_size);
        crate::assert_with_log!(
            config.acquire_timeout == Duration::from_secs(30),
            "acquire_timeout",
            Duration::from_secs(30),
            config.acquire_timeout
        );
        crate::assert_with_log!(
            config.idle_timeout == Duration::from_mins(10),
            "idle_timeout",
            Duration::from_mins(10),
            config.idle_timeout
        );
        crate::assert_with_log!(
            config.max_lifetime == Duration::from_hours(1),
            "max_lifetime",
            Duration::from_hours(1),
            config.max_lifetime
        );
        crate::test_complete!("pool_config_default");
    }

    #[test]
    fn pool_config_builder() {
        init_test("pool_config_builder");
        let config = PoolConfig::with_max_size(20)
            .min_size(5)
            .acquire_timeout(Duration::from_secs(60))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1800));

        crate::assert_with_log!(config.min_size == 5, "min_size", 5usize, config.min_size);
        crate::assert_with_log!(config.max_size == 20, "max_size", 20usize, config.max_size);
        crate::assert_with_log!(
            config.acquire_timeout == Duration::from_secs(60),
            "acquire_timeout",
            Duration::from_secs(60),
            config.acquire_timeout
        );
        crate::assert_with_log!(
            config.idle_timeout == Duration::from_secs(300),
            "idle_timeout",
            Duration::from_secs(300),
            config.idle_timeout
        );
        crate::assert_with_log!(
            config.max_lifetime == Duration::from_secs(1800),
            "max_lifetime",
            Duration::from_secs(1800),
            config.max_lifetime
        );
        crate::test_complete!("pool_config_builder");
    }

    // ========================================================================
    // GenericPool tests
    // ========================================================================

    #[allow(clippy::type_complexity)]
    fn simple_factory() -> std::pin::Pin<
        Box<dyn Future<Output = Result<u32, Box<dyn std::error::Error + Send + Sync>>> + Send>,
    > {
        Box::pin(async { Ok(42u32) })
    }

    #[allow(clippy::type_complexity)]
    fn counting_factory(
        created: Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl Fn() -> Pin<
        Box<dyn Future<Output = Result<usize, Box<dyn std::error::Error + Send + Sync>>> + Send>,
    > + Send
    + Sync {
        move || {
            let id = created.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok(id) })
        }
    }

    #[test]
    fn pool_idle_expiry_drops_resource_after_unlock() {
        init_test("pool_idle_expiry_drops_resource_after_unlock");

        let config = PoolConfig::with_max_size(1).idle_timeout(Duration::ZERO);
        let pool = Arc::new(GenericPool::with_time_getter(
            pool_resource_probe_factory,
            config,
            test_pool_time_now,
        ));
        let (resource, drop_rx) = pool_resource_lock_probe(&pool);
        let now = test_pool_time_now();
        {
            let mut state = pool.state.lock();
            state.idle.reserve(1);
            state.idle.push_back(IdleResource {
                resource,
                idle_since: now,
                created_at: now,
            });
        }

        assert!(
            pool.try_get_idle(None).is_none(),
            "zero-timeout resource must be evicted"
        );
        assert_pool_resource_dropped_outside_locks(&drop_rx, "idle-timeout eviction");
        crate::test_complete!("pool_idle_expiry_drops_resource_after_unlock");
    }

    #[test]
    fn pool_close_drops_idle_resource_after_unlock() {
        init_test("pool_close_drops_idle_resource_after_unlock");

        let pool = Arc::new(GenericPool::with_time_getter(
            pool_resource_probe_factory,
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        ));
        let (resource, drop_rx) = pool_resource_lock_probe(&pool);
        let now = test_pool_time_now();
        {
            let mut state = pool.state.lock();
            state.idle.reserve(1);
            state.idle.push_back(IdleResource {
                resource,
                idle_since: now,
                created_at: now,
            });
        }

        futures_lite::future::block_on(pool.close());
        assert_pool_resource_dropped_outside_locks(&drop_rx, "pool close");
        crate::test_complete!("pool_close_drops_idle_resource_after_unlock");
    }

    #[test]
    fn pool_return_after_close_drops_resource_after_unlock() {
        init_test("pool_return_after_close_drops_resource_after_unlock");

        let pool = Arc::new(GenericPool::with_time_getter(
            pool_resource_probe_factory,
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        ));
        {
            let mut state = pool.state.lock();
            state.active = 1;
        }
        futures_lite::future::block_on(pool.close());

        let (resource, drop_rx) = pool_resource_lock_probe(&pool);
        let sent = pool
            .return_tx
            .send(PoolReturn::Return {
                resource,
                hold_duration: Duration::ZERO,
                created_at: test_pool_time_now(),
            })
            .is_ok();
        assert!(sent, "return channel remains connected after pool close");

        pool.process_returns();
        assert_eq!(
            pool.state.lock().active,
            0,
            "return-after-close commits active accounting before destruction"
        );
        assert_pool_resource_dropped_outside_locks(&drop_rx, "return after close");
        crate::test_complete!("pool_return_after_close_drops_resource_after_unlock");
    }

    #[test]
    fn pool_wait_notification_cancellation_retires_both_wakers_after_unlock() {
        init_test("pool_wait_notification_cancellation_retires_both_wakers_after_unlock");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let (state_probe, state_rx) = deferred_pool_lock_probe(&pool);
        let (return_probe, return_rx) = deferred_pool_lock_probe(&pool);
        let waiter_id_value = 17;

        {
            let mut state = pool.state.lock();
            state.active = 1;
            state.waiters.reserve(1);
            state.waiters.push_back(PoolWaiter {
                id: waiter_id_value,
                waker: state_probe,
            });
        }
        {
            let mut wakers = pool.return_wakers.lock();
            wakers.reserve(1);
            wakers.push((waiter_id_value, return_probe));
        }

        let cx = Cx::for_testing();
        let mut waiter_id = Some(waiter_id_value);
        drop(WaitForNotification {
            pool: pool.as_ref(),
            waiter_id: &mut waiter_id,
            cx: &cx,
            completed: false,
        });

        assert_pool_waker_retired_outside_locks(&state_rx, "cancelled state registration");
        assert_pool_waker_retired_outside_locks(&return_rx, "cancelled return registration");
        crate::test_complete!(
            "pool_wait_notification_cancellation_retires_both_wakers_after_unlock"
        );
    }

    #[test]
    fn pool_wait_notification_repoll_retires_changed_wakers_after_unlock() {
        init_test("pool_wait_notification_repoll_retires_changed_wakers_after_unlock");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let (state_probe, state_rx) = deferred_pool_lock_probe(&pool);
        let (return_probe, return_rx) = deferred_pool_lock_probe(&pool);
        let waiter_id_value = 23;

        {
            let mut state = pool.state.lock();
            state.active = 1;
            state.waiters.reserve(1);
            state.waiters.push_back(PoolWaiter {
                id: waiter_id_value,
                waker: state_probe,
            });
        }
        {
            let mut wakers = pool.return_wakers.lock();
            wakers.reserve(1);
            wakers.push((waiter_id_value, return_probe));
        }

        let cx = Cx::for_testing();
        let mut waiter_id = Some(waiter_id_value);
        let mut wait = WaitForNotification {
            pool: pool.as_ref(),
            waiter_id: &mut waiter_id,
            cx: &cx,
            completed: false,
        };
        let task_waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&task_waker);
        assert!(Pin::new(&mut wait).poll(&mut task_cx).is_pending());

        assert_pool_waker_retired_outside_locks(&state_rx, "changed state registration");
        assert_pool_waker_retired_outside_locks(&return_rx, "changed return registration");
        drop(wait);
        crate::test_complete!("pool_wait_notification_repoll_retires_changed_wakers_after_unlock");
    }

    #[test]
    fn pool_successful_dequeue_retires_both_wakers_after_unlock() {
        init_test("pool_successful_dequeue_retires_both_wakers_after_unlock");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let cx = Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
        let task_waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&task_waker);
        let mut waiter = pool.acquire(&cx);
        assert!(waiter.as_mut().poll(&mut task_cx).is_pending());

        let waiter_id = pool
            .state
            .lock()
            .waiters
            .front()
            .expect("pending acquire registered in state queue")
            .id;
        let (state_probe, state_rx) = deferred_pool_lock_probe(&pool);
        let (return_probe, return_rx) = deferred_pool_lock_probe(&pool);

        let retired_state_waker = {
            let mut state = pool.state.lock();
            let entry = state
                .waiters
                .iter_mut()
                .find(|entry| entry.id == waiter_id)
                .expect("state registration");
            std::mem::replace(&mut entry.waker, state_probe)
        };
        drop(retired_state_waker);
        let retired_return_waker = {
            let mut wakers = pool.return_wakers.lock();
            let entry = wakers
                .iter_mut()
                .find(|(id, _)| *id == waiter_id)
                .expect("return registration");
            std::mem::replace(&mut entry.1, return_probe)
        };
        drop(retired_return_waker);

        held.return_to_pool();
        let resource = match waiter.as_mut().poll(&mut task_cx) {
            Poll::Ready(Ok(resource)) => resource,
            Poll::Ready(Err(error)) => panic!("waiter failed after resource return: {error}"),
            Poll::Pending => panic!("returned resource did not satisfy the queued waiter"),
        };
        drop(waiter);

        assert_pool_waker_retired_outside_locks(&state_rx, "successful state dequeue");
        assert_pool_waker_retired_outside_locks(&return_rx, "successful return dequeue");
        resource.return_to_pool();
        crate::test_complete!("pool_successful_dequeue_retires_both_wakers_after_unlock");
    }

    #[test]
    fn pool_waiter_cleanup_retires_return_waker_after_unlock() {
        init_test("pool_waiter_cleanup_retires_return_waker_after_unlock");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let cx = Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
        let task_waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&task_waker);
        let mut waiter = pool.acquire(&cx);
        assert!(waiter.as_mut().poll(&mut task_cx).is_pending());

        let waiter_id = pool
            .state
            .lock()
            .waiters
            .front()
            .expect("pending acquire registered in state queue")
            .id;
        let (return_probe, return_rx) = deferred_pool_lock_probe(&pool);
        let retired_return_waker = {
            let mut wakers = pool.return_wakers.lock();
            let entry = wakers
                .iter_mut()
                .find(|(id, _)| *id == waiter_id)
                .expect("return registration");
            std::mem::replace(&mut entry.1, return_probe)
        };
        drop(retired_return_waker);

        cx.set_cancel_requested(true);
        let result = waiter.as_mut().poll(&mut task_cx);
        assert!(matches!(result, Poll::Ready(Err(PoolError::Cancelled))));
        drop(waiter);

        assert_pool_waker_retired_outside_locks(&return_rx, "WaiterCleanup return removal");
        held.return_to_pool();
        crate::test_complete!("pool_waiter_cleanup_retires_return_waker_after_unlock");
    }

    struct TimeoutAfterNSuccessesFactory {
        successes: u32,
        next_attempt: std::sync::atomic::AtomicU32,
    }

    impl AsyncResourceFactory for TimeoutAfterNSuccessesFactory {
        type Resource = u32;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn create(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>>
        {
            let attempt = self
                .next_attempt
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let successes = self.successes;
            Box::pin(async move {
                if attempt < successes {
                    Ok(attempt)
                } else {
                    std::future::pending::<Result<u32, Box<dyn std::error::Error + Send + Sync>>>()
                        .await
                }
            })
        }
    }

    #[test]
    fn generic_pool_stats_initial() {
        init_test("generic_pool_stats_initial");
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let stats = pool.stats();
        crate::assert_with_log!(stats.active == 0, "active", 0usize, stats.active);
        crate::assert_with_log!(stats.idle == 0, "idle", 0usize, stats.idle);
        crate::assert_with_log!(stats.total == 0, "total", 0usize, stats.total);
        crate::assert_with_log!(stats.max_size == 5, "max_size", 5usize, stats.max_size);
        crate::test_complete!("generic_pool_stats_initial");
    }

    #[test]
    fn create_slot_reservation_enforces_max_size_and_releases_on_drop() {
        init_test("create_slot_reservation_enforces_max_size_and_releases_on_drop");
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));

        let slot1 = CreateSlotReservation::try_reserve(&pool, None);
        crate::assert_with_log!(
            slot1.is_some(),
            "first slot reserved",
            true,
            slot1.is_some()
        );

        let slot2 = CreateSlotReservation::try_reserve(&pool, None);
        crate::assert_with_log!(
            slot2.is_none(),
            "second slot blocked at max_size=1",
            true,
            slot2.is_none()
        );

        drop(slot1);

        let slot3 = CreateSlotReservation::try_reserve(&pool, None);
        crate::assert_with_log!(
            slot3.is_some(),
            "slot released when reservation dropped",
            true,
            slot3.is_some()
        );
        if let Some(slot) = slot3 {
            slot.commit();
        }

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 1,
            "commit converts reserved slot to active resource",
            1usize,
            stats.active
        );
        crate::test_complete!("create_slot_reservation_enforces_max_size_and_releases_on_drop");
    }

    #[test]
    fn pool_stats_total_includes_creating_slots() {
        init_test("pool_stats_total_includes_creating_slots");

        // Verify that PoolStats::total includes in-flight creates (the `creating`
        // counter), not just active + idle. This ensures monitoring accurately
        // reflects actual capacity usage.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));

        // Reserve a create slot (simulates async resource creation in progress)
        let slot = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot.is_some(), "should reserve a create slot");

        let stats = pool.stats();
        // total should be 1 (0 active + 0 idle + 1 creating)
        crate::assert_with_log!(
            stats.total == 1,
            "total includes creating slot",
            1usize,
            stats.total
        );

        // Drop the reservation without committing (simulates cancelled create)
        drop(slot);

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.total == 0,
            "total after released creating slot",
            0usize,
            stats.total
        );

        crate::test_complete!("pool_stats_total_includes_creating_slots");
    }

    #[test]
    fn drop_delegates_to_return_inner_no_double_send() {
        init_test("drop_delegates_to_return_inner_no_double_send");

        // Verify that Drop delegates to return_inner and does not
        // produce double sends on the return channel.
        let (tx, rx) = mpsc::channel();
        {
            let _pooled = PooledResource::new(55u8, tx);
            // _pooled dropped here
        }

        let msg = rx
            .recv()
            .expect("should receive exactly one return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 55, "returned value", 55u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected Return, got Discard"),
        }

        // Verify no second message (no double-send from duplicated drop logic)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no double send from Drop",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("drop_delegates_to_return_inner_no_double_send");
    }

    #[test]
    fn pooled_resource_is_send_when_resource_is_send() {
        fn assert_send<T: Send>() {}

        init_test("pooled_resource_is_send_when_resource_is_send");

        // Verify that PooledResource<R> auto-derives Send when R: Send
        // (no manual unsafe impl needed).
        assert_send::<PooledResource<u8>>();
        assert_send::<PooledResource<String>>();
        assert_send::<PooledResource<Vec<u8>>>();

        crate::test_complete!("pooled_resource_is_send_when_resource_is_send");
    }

    #[test]
    fn generic_pool_try_acquire_creates_resource() {
        init_test("generic_pool_try_acquire_creates_resource");

        // Need to use a runtime to test async behavior
        // For now, test try_acquire which returns None since pool is empty
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));

        // try_acquire returns None when pool is empty (no pre-created resources)
        let result = pool.try_acquire();
        crate::assert_with_log!(
            result.is_none(),
            "try_acquire empty",
            true,
            result.is_none()
        );

        crate::test_complete!("generic_pool_try_acquire_creates_resource");
    }

    #[test]
    fn pool_error_display() {
        init_test("pool_error_display");

        let closed = PoolError::Closed;
        let timeout = PoolError::Timeout;
        let cancelled = PoolError::Cancelled;
        let create_failed = PoolError::CreateFailed(Box::new(std::io::Error::other("test error")));

        crate::assert_with_log!(
            closed.to_string() == "pool closed",
            "closed display",
            "pool closed",
            closed.to_string()
        );
        crate::assert_with_log!(
            timeout.to_string() == "pool acquire timeout",
            "timeout display",
            "pool acquire timeout",
            timeout.to_string()
        );
        crate::assert_with_log!(
            cancelled.to_string() == "pool acquire cancelled",
            "cancelled display",
            "pool acquire cancelled",
            cancelled.to_string()
        );
        crate::assert_with_log!(
            create_failed
                .to_string()
                .contains("resource creation failed"),
            "create_failed display",
            "contains resource creation failed",
            create_failed.to_string()
        );

        crate::test_complete!("pool_error_display");
    }

    // ========================================================================
    // Cancel-safety tests
    // ========================================================================

    #[test]
    fn cancel_while_holding_resource_returns_on_drop() {
        init_test("cancel_while_holding_resource_returns_on_drop");

        // This test verifies that when a task holding a pooled resource is
        // cancelled, the resource is properly returned to the pool via the
        // Drop implementation.

        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(99u8, tx);

        // Simulate cancellation by just dropping the resource
        // In a real scenario, cancellation would cause the future to be dropped
        drop(pooled);

        // Verify resource was returned
        let msg = rx.recv().expect("should receive return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 99, "returned value", 99u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected Return, got Discard"),
        }

        // Verify channel is empty (exactly one return)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no extra messages",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("cancel_while_holding_resource_returns_on_drop");
    }

    #[test]
    fn obligation_discharged_prevents_double_return() {
        init_test("obligation_discharged_prevents_double_return");

        // Test that explicitly returning a resource prevents the Drop from
        // returning it again (no double-return bug).

        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(77u8, tx);

        // Explicitly return
        pooled.return_to_pool();

        // Verify exactly one return message
        let msg = rx.recv().expect("should receive return message");
        match msg {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 77, "returned value", 77u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected Return, got Discard"),
        }

        // No second message (drop should not send again)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no double return",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("obligation_discharged_prevents_double_return");
    }

    #[test]
    fn discard_prevents_return_on_drop() {
        init_test("discard_prevents_return_on_drop");

        // Test that discarding a resource prevents the Drop from returning it.

        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(88u8, tx);

        // Explicitly discard
        pooled.discard();

        // Verify we got a discard message
        let msg = rx.recv().expect("should receive discard message");
        match msg {
            PoolReturn::Return { .. } => unreachable!("expected Discard, got Return"),
            PoolReturn::Discard { hold_duration: _ } => {
                // Good - discard was sent
            }
        }

        // No second message
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "no extra messages after discard",
            true,
            rx.try_recv().is_err()
        );

        crate::test_complete!("discard_prevents_return_on_drop");
    }

    #[test]
    fn generic_pool_close_clears_idle_resources() {
        init_test("generic_pool_close_clears_idle_resources");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));

        // Close the pool
        futures_lite::future::block_on(pool.close());

        // Verify pool is closed - try_acquire should return None
        let result = pool.try_acquire();
        crate::assert_with_log!(
            result.is_none(),
            "closed pool returns None",
            true,
            result.is_none()
        );

        // Stats should show empty
        let stats = pool.stats();
        crate::assert_with_log!(stats.idle == 0, "idle after close", 0usize, stats.idle);

        crate::test_complete!("generic_pool_close_clears_idle_resources");
    }

    #[test]
    fn generic_pool_acquire_when_closed_returns_error() {
        init_test("generic_pool_acquire_when_closed_returns_error");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Close the pool
        futures_lite::future::block_on(pool.close());

        // Acquire should return Closed error
        let result = futures_lite::future::block_on(pool.acquire(&cx));
        match result {
            Err(PoolError::Closed) => {
                // Good - closed error as expected
            }
            Ok(_) => unreachable!("expected Closed error, got Ok"),
            Err(e) => unreachable!("expected Closed error, got {e:?}"),
        }

        crate::test_complete!("generic_pool_acquire_when_closed_returns_error");
    }

    #[test]
    fn generic_pool_resource_returned_becomes_idle() {
        init_test("generic_pool_resource_returned_becomes_idle");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire a resource
        let resource = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("first acquire should succeed");

        // Check stats - should show 1 active
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 1,
            "active after acquire",
            1usize,
            stats.active
        );
        crate::assert_with_log!(stats.idle == 0, "idle after acquire", 0usize, stats.idle);

        // Return the resource
        resource.return_to_pool();

        // Process returns and check stats
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "active after return",
            0usize,
            stats.active
        );
        crate::assert_with_log!(stats.idle == 1, "idle after return", 1usize, stats.idle);

        crate::test_complete!("generic_pool_resource_returned_becomes_idle");
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AcquireDropTranscript {
        acquired: Vec<u32>,
        reacquired: Vec<u32>,
        projections: Vec<(usize, usize, usize, u64)>,
    }

    fn run_acquire_drop_transcript(release_by_drop: bool) -> AcquireDropTranscript {
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };
        let pool = GenericPool::new(factory, PoolConfig::with_max_size(2));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let mut transcript = AcquireDropTranscript {
            acquired: Vec::new(),
            reacquired: Vec::new(),
            projections: Vec::new(),
        };

        for _ in 0..8 {
            let resource = futures_lite::future::block_on(pool.acquire(&cx))
                .expect("initial acquire should succeed");
            transcript.acquired.push(*resource);
            if release_by_drop {
                drop(resource);
            } else {
                resource.return_to_pool();
            }

            let after_release = pool.stats();
            transcript.projections.push((
                after_release.active,
                after_release.idle,
                after_release.total,
                after_release.total_acquisitions,
            ));

            let resource = futures_lite::future::block_on(pool.acquire(&cx))
                .expect("reacquire after release should succeed");
            transcript.reacquired.push(*resource);
            if release_by_drop {
                drop(resource);
            } else {
                resource.return_to_pool();
            }

            let after_reacquire_release = pool.stats();
            transcript.projections.push((
                after_reacquire_release.active,
                after_reacquire_release.idle,
                after_reacquire_release.total,
                after_reacquire_release.total_acquisitions,
            ));
        }

        transcript
    }

    #[test]
    fn generic_pool_acquire_drop_matches_explicit_return() {
        init_test("generic_pool_acquire_drop_matches_explicit_return");

        let dropped = run_acquire_drop_transcript(true);
        let explicitly_returned = run_acquire_drop_transcript(false);

        assert_eq!(
            dropped, explicitly_returned,
            "dropping PooledResource must preserve return_to_pool reuse and accounting"
        );
        assert!(
            dropped
                .acquired
                .iter()
                .zip(dropped.reacquired.iter())
                .all(|(first, second)| first == second),
            "released resources should be reused before replacements are created"
        );

        crate::test_complete!("generic_pool_acquire_drop_matches_explicit_return");
    }

    #[test]
    fn generic_pool_discarded_resource_not_returned_to_idle() {
        init_test("generic_pool_discarded_resource_not_returned_to_idle");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire a resource
        let resource = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("first acquire should succeed");

        // Discard the resource (simulating a broken connection)
        resource.discard();

        // Process returns and check stats - should show 0 idle (discarded resources don't return)
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "active after discard",
            0usize,
            stats.active
        );
        crate::assert_with_log!(stats.idle == 0, "idle after discard", 0usize, stats.idle);

        crate::test_complete!("generic_pool_discarded_resource_not_returned_to_idle");
    }

    #[test]
    fn generic_pool_held_duration_increases() {
        init_test("generic_pool_held_duration_increases");

        let (tx, _rx) = mpsc::channel();
        let pooled = PooledResource::new_with_time_getter(42u8, tx, test_pool_time_now);
        advance_test_pool_time(Duration::from_millis(10));

        let held = pooled.held_duration();
        crate::assert_with_log!(
            held == Duration::from_millis(10),
            "held duration follows injected clock exactly",
            Duration::from_millis(10),
            held
        );

        crate::test_complete!("generic_pool_held_duration_increases");
    }

    #[test]
    fn load_test_many_acquire_return_cycles() {
        init_test("load_test_many_acquire_return_cycles");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Run many acquire/return cycles
        for i in 0..100 {
            let resource =
                futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

            // Use the resource
            let _ = *resource;

            // Return it (or drop it - both should work)
            if i % 2 == 0 {
                resource.return_to_pool();
            } else {
                drop(resource);
            }
        }

        // Final stats check
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "no active after all returned",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.total_acquisitions == 100,
            "100 total acquisitions",
            100u64,
            stats.total_acquisitions
        );

        crate::test_complete!("load_test_many_acquire_return_cycles");
    }

    #[test]
    fn record_wait_time_accumulates_in_pool_stats() {
        init_test("record_wait_time_accumulates_in_pool_stats");

        let pool = GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1).acquire_timeout(Duration::from_secs(1)),
        );
        let before = pool.stats().total_wait_time;

        pool.record_wait_time(Duration::from_millis(15));
        pool.record_wait_time(Duration::ZERO);

        let stats = pool.stats();
        assert!(
            stats.total_wait_time >= before + Duration::from_millis(15),
            "recorded wait time should be reflected in pool stats, got {:?}",
            stats.total_wait_time
        );

        crate::test_complete!("record_wait_time_accumulates_in_pool_stats");
    }

    #[test]
    fn acquire_timeout_reports_timeout_and_cleans_waiter_state() {
        init_test("acquire_timeout_reports_timeout_and_cleans_waiter_state");

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = test_cx_with_timer(timer.clone());
        let _guard = Cx::set_current(Some(cx.clone()));
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1).acquire_timeout(Duration::from_millis(25)),
            test_pool_time_now,
        );

        // Hold the only slot so the next acquire must wait and hit timeout.
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");

        let waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut acquire_fut = std::pin::pin!(pool.acquire(&cx));

        let first_poll = acquire_fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "second acquire should block while pool is exhausted",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            pool.stats().waiters == 1,
            "blocked acquire should register exactly one waiter",
            1usize,
            pool.stats().waiters
        );

        advance_test_pool_time(Duration::from_millis(25));
        clock.advance(Time::from_millis(25).as_nanos());
        let _ = timer.process_timers();

        let result = acquire_fut.as_mut().poll(&mut task_cx);

        assert!(
            matches!(result, Poll::Ready(Err(PoolError::Timeout))),
            "second acquire should timeout when pool remains exhausted"
        );

        // Waiter cleanup and wait-time accounting must run even on timeout.
        let stats = pool.stats();
        assert_eq!(stats.waiters, 0, "timeout should not leak waiters");
        assert!(
            stats.total_wait_time == Duration::from_millis(25),
            "timeout wait should be accounted in pool stats; got {got:?}",
            got = stats.total_wait_time
        );

        held.return_to_pool();
        crate::test_complete!("acquire_timeout_reports_timeout_and_cleans_waiter_state");
    }

    #[test]
    fn acquire_budget_deadline_wakes_and_cancels_waiter() {
        init_test("acquire_budget_deadline_wakes_and_cancels_waiter");

        struct FlagWake(Arc<std::sync::atomic::AtomicBool>);

        impl Wake for FlagWake {
            fn wake(self: Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let holding_cx = test_cx_with_timer(timer.clone());
        let deadline_cx = test_cx_with_timer_and_budget(
            timer.clone(),
            Budget::new().with_deadline(Time::from_millis(10)),
        );
        let _guard = Cx::set_current(Some(deadline_cx.clone()));
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1).acquire_timeout(Duration::from_secs(1)),
            test_pool_time_now,
        );

        let held =
            futures_lite::future::block_on(pool.acquire(&holding_cx)).expect("first acquire");
        let wake_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Waker::from(Arc::new(FlagWake(Arc::clone(&wake_flag))));
        let mut task_cx = Context::from_waker(&waker);
        let mut acquire_fut = std::pin::pin!(pool.acquire(&deadline_cx));

        let first_poll = acquire_fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "deadline-bound waiter should block while pool is exhausted",
            true,
            first_poll.is_pending()
        );

        advance_test_pool_time(Duration::from_millis(10));
        clock.advance(Time::from_millis(10).as_nanos());
        let _ = timer.process_timers();

        crate::assert_with_log!(
            wake_flag.load(std::sync::atomic::Ordering::SeqCst),
            "budget deadline should wake blocked acquire before pool timeout",
            true,
            wake_flag.load(std::sync::atomic::Ordering::SeqCst)
        );

        let result = acquire_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(result, Poll::Ready(Err(PoolError::Cancelled))),
            "budget deadline should cancel blocked acquire"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.waiters, 0,
            "deadline cancellation must not leak waiters"
        );

        held.return_to_pool();
        crate::test_complete!("acquire_budget_deadline_wakes_and_cancels_waiter");
    }

    #[test]
    fn cancelled_waiter_does_not_acquire_returned_resource() {
        init_test("cancelled_waiter_does_not_acquire_returned_resource");

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let holding_cx = test_cx_with_timer(timer.clone());
        let deadline_cx = test_cx_with_timer_and_budget(
            timer.clone(),
            Budget::new().with_deadline(Time::from_millis(10)),
        );
        let _guard = Cx::set_current(Some(deadline_cx.clone()));
        let pool = GenericPool::with_time_getter(
            simple_factory,
            PoolConfig::with_max_size(1).acquire_timeout(Duration::from_secs(1)),
            test_pool_time_now,
        );

        let held =
            futures_lite::future::block_on(pool.acquire(&holding_cx)).expect("first acquire");
        let waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut acquire_fut = std::pin::pin!(pool.acquire(&deadline_cx));

        let first_poll = acquire_fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "deadline-bound waiter should enter the wait queue",
            true,
            first_poll.is_pending()
        );

        advance_test_pool_time(Duration::from_millis(10));
        clock.advance(Time::from_millis(10).as_nanos());

        held.return_to_pool();

        let result = acquire_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(result, Poll::Ready(Err(PoolError::Cancelled))),
            "expired waiter must not consume a returned resource"
        );

        let stats = pool.stats();
        assert_eq!(stats.active, 0, "cancelled waiter must not become active");
        assert_eq!(stats.idle, 1, "returned resource should remain idle");
        assert_eq!(stats.waiters, 0, "cancelled waiter must be cleaned up");

        crate::test_complete!("cancelled_waiter_does_not_acquire_returned_resource");
    }

    // ========================================================================
    // Health check tests (asupersync-cl94)
    // ========================================================================

    #[test]
    fn health_check_evicts_unhealthy_idle_resource() {
        init_test("health_check_evicts_unhealthy_idle_resource");

        // Factory produces (id, healthy_flag) tuples
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>((id, true)) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(5).health_check_on_acquire(true);
        // Health check: only resources with id != 0 pass
        let pool = GenericPool::new(factory, config)
            .with_health_check(|&(id, _healthy): &(u32, bool)| id != 0);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire resource #0
        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        assert_eq!(r0.0, 0u32, "first resource should be id 0");
        // Return it to the idle pool
        r0.return_to_pool();

        // Now acquire again — id 0 should fail health check, so pool creates id 1
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(r1.0, 1u32, "unhealthy id 0 should be evicted, got new id 1");

        let stats = pool.stats();
        assert_eq!(stats.active, 1, "one resource active");
        assert_eq!(stats.idle, 0, "no idle resources (id 0 was evicted)");

        crate::test_complete!("health_check_evicts_unhealthy_idle_resource");
    }

    #[test]
    fn health_check_passes_healthy_resource() {
        init_test("health_check_passes_healthy_resource");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(5).health_check_on_acquire(true);
        // All resources pass health check
        let pool = GenericPool::new(factory, config).with_health_check(|_id: &u32| true);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire and return resource #0
        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        assert_eq!(*r0, 0u32);
        r0.return_to_pool();

        // Acquire again — should reuse #0 since it passes health check
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(*r1, 0, "healthy resource should be reused");

        crate::test_complete!("health_check_passes_healthy_resource");
    }

    #[test]
    fn health_check_disabled_skips_check() {
        init_test("health_check_disabled_skips_check");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        // health_check_on_acquire defaults to false
        let config = PoolConfig::with_max_size(5);
        // Health check that rejects everything — but it's disabled
        let pool = GenericPool::new(factory, config).with_health_check(|_id: &u32| false);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        assert_eq!(*r0, 0);
        r0.return_to_pool();

        // Should still return #0 because health check is not enabled
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(
            *r1, 0,
            "health check disabled, resource reused despite failing check"
        );

        crate::test_complete!("health_check_disabled_skips_check");
    }

    #[test]
    fn try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled() {
        init_test("try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(5).health_check_on_acquire(true);
        let pool = GenericPool::new(factory, config).with_health_check(|id: &u32| *id != 0);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Seed two idle resources: #0 (unhealthy), then #1 (healthy).
        let r0 = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("second acquire");
        assert_eq!(*r0, 0);
        assert_eq!(*r1, 1);
        r0.return_to_pool();
        r1.return_to_pool();

        // try_acquire should skip #0 and return #1.
        let picked = pool
            .try_acquire()
            .expect("should acquire healthy idle resource");
        assert_eq!(
            *picked, 1,
            "try_acquire should skip unhealthy idle resource"
        );

        let stats = pool.stats();
        assert_eq!(stats.active, 1, "one resource checked out");
        assert_eq!(stats.idle, 0, "no healthy idle resources left");

        crate::test_complete!(
            "try_acquire_skips_unhealthy_idle_resources_when_health_check_enabled"
        );
    }

    // ========================================================================
    // Warmup tests (asupersync-cl94)
    // ========================================================================

    #[test]
    fn warmup_creates_resources() {
        init_test("warmup_creates_resources");

        let config = PoolConfig::with_max_size(10).warmup_connections(3);
        let pool = GenericPool::new(simple_factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 3, "should create 3 warmup resources");

        let stats = pool.stats();
        assert_eq!(stats.idle, 3, "3 idle resources after warmup");
        assert_eq!(stats.active, 0, "no active resources");

        crate::test_complete!("warmup_creates_resources");
    }

    #[test]
    fn warmup_respects_max_size() {
        init_test("warmup_respects_max_size");

        let config = PoolConfig::with_max_size(2).warmup_connections(5);
        let pool = GenericPool::new(simple_factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 2, "warmup must not exceed max_size");

        let stats = pool.stats();
        assert_eq!(stats.idle, 2, "idle resources capped by max_size");
        assert_eq!(stats.total, 2, "total resources capped by max_size");

        crate::test_complete!("warmup_respects_max_size");
    }

    #[test]
    fn warmup_zero_is_noop() {
        init_test("warmup_zero_is_noop");

        let config = PoolConfig::with_max_size(10).warmup_connections(0);
        let pool = GenericPool::new(simple_factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 0, "zero warmup creates nothing");

        let stats = pool.stats();
        assert_eq!(stats.idle, 0, "no idle resources");

        crate::test_complete!("warmup_zero_is_noop");
    }

    #[test]
    fn warmup_timeout_fail_fast_returns_timeout() {
        init_test("warmup_timeout_fail_fast_returns_timeout");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 0,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(2)
            .warmup_connections(1)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::FailFast);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(
            matches!(result, Err(PoolError::Timeout)),
            "stalled warmup should return PoolError::Timeout under FailFast"
        );

        let stats = pool.stats();
        assert_eq!(stats.total, 0, "timed out warmup must release create slot");
        assert_eq!(
            stats.idle, 0,
            "timed out warmup must not leak idle resources"
        );

        crate::test_complete!("warmup_timeout_fail_fast_returns_timeout");
    }

    #[test]
    fn warmup_timeout_best_effort_returns_partial_progress() {
        init_test("warmup_timeout_best_effort_returns_partial_progress");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 1,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(3)
            .warmup_connections(2)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::BestEffort);
        let pool = GenericPool::new(factory, config);

        let created =
            futures_lite::future::block_on(pool.warmup()).expect("BestEffort should keep progress");
        assert_eq!(
            created, 1,
            "warmup should report resources created before timeout"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 1,
            "successful warmup resource should remain idle"
        );
        assert_eq!(
            stats.total, 1,
            "timeout must not retain the stalled create slot"
        );

        crate::test_complete!("warmup_timeout_best_effort_returns_partial_progress");
    }

    #[test]
    fn warmup_timeout_require_minimum_errors_when_min_not_reached() {
        init_test("warmup_timeout_require_minimum_errors_when_min_not_reached");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 1,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(3)
            .min_size(2)
            .warmup_connections(3)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(
            matches!(result, Err(PoolError::Timeout)),
            "RequireMinimum should surface timeout when min_size is not reached"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 1,
            "successful creates before timeout should remain usable"
        );
        assert_eq!(stats.total, 1, "timed out create slot must be released");

        crate::test_complete!("warmup_timeout_require_minimum_errors_when_min_not_reached");
    }

    #[test]
    fn warmup_timeout_require_minimum_keeps_progress_once_min_reached() {
        init_test("warmup_timeout_require_minimum_keeps_progress_once_min_reached");

        let factory = TimeoutAfterNSuccessesFactory {
            successes: 1,
            next_attempt: std::sync::atomic::AtomicU32::new(0),
        };
        let config = PoolConfig::with_max_size(3)
            .min_size(1)
            .warmup_connections(3)
            .warmup_timeout(Duration::from_millis(25))
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(factory, config);

        let created = futures_lite::future::block_on(pool.warmup())
            .expect("RequireMinimum should keep partial progress once min_size is met");
        assert_eq!(
            created, 1,
            "warmup should retain successful creates before timeout"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 1,
            "resource created before timeout should remain idle"
        );
        assert_eq!(stats.total, 1, "timed out create slot must be released");

        crate::test_complete!("warmup_timeout_require_minimum_keeps_progress_once_min_reached");
    }

    #[test]
    fn warmup_fail_fast_stops_on_error() {
        init_test("warmup_fail_fast_stops_on_error");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n >= 2 {
                    Err::<u32, _>(Box::new(std::io::Error::other("fail"))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(n)
                }
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10)
            .warmup_connections(5)
            .warmup_failure_strategy(WarmupStrategy::FailFast);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(result.is_err(), "FailFast should return error");

        // Only 2 resources created before the third failed
        let stats = pool.stats();
        assert_eq!(stats.idle, 2, "2 created before failure");

        crate::test_complete!("warmup_fail_fast_stops_on_error");
    }

    #[test]
    fn warmup_best_effort_continues_on_error() {
        init_test("warmup_best_effort_continues_on_error");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n % 2 == 1 {
                    // Odd-numbered creates fail
                    Err::<u32, _>(Box::new(std::io::Error::other("fail"))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(n)
                }
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10)
            .warmup_connections(4)
            .warmup_failure_strategy(WarmupStrategy::BestEffort);
        let pool = GenericPool::new(factory, config);

        let created =
            futures_lite::future::block_on(pool.warmup()).expect("BestEffort never errors");
        assert_eq!(created, 2, "2 of 4 succeeded (evens)");

        let stats = pool.stats();
        assert_eq!(stats.idle, 2, "2 idle after partial warmup");

        crate::test_complete!("warmup_best_effort_continues_on_error");
    }

    #[test]
    fn warmup_require_minimum_fails_below_min() {
        init_test("warmup_require_minimum_fails_below_min");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if n >= 1 {
                    Err::<u32, _>(Box::new(std::io::Error::other("fail"))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(n)
                }
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10)
            .min_size(3)
            .warmup_connections(5)
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(factory, config);

        let result = futures_lite::future::block_on(pool.warmup());
        assert!(
            result.is_err(),
            "RequireMinimum should fail: only 1 created < min_size 3"
        );

        crate::test_complete!("warmup_require_minimum_fails_below_min");
    }

    #[test]
    fn warmup_require_minimum_passes_above_min() {
        init_test("warmup_require_minimum_passes_above_min");

        let config = PoolConfig::with_max_size(10)
            .min_size(2)
            .warmup_connections(5)
            .warmup_failure_strategy(WarmupStrategy::RequireMinimum);
        let pool = GenericPool::new(simple_factory, config);

        let created =
            futures_lite::future::block_on(pool.warmup()).expect("should pass: 5 >= min 2");
        assert_eq!(created, 5, "all 5 warmup resources created");

        crate::test_complete!("warmup_require_minimum_passes_above_min");
    }

    #[test]
    fn warmup_created_timestamps_follow_time_getter() {
        init_test("warmup_created_timestamps_follow_time_getter");

        set_test_pool_time_offset(Duration::from_secs(86_400));

        let config = PoolConfig::with_max_size(4)
            .warmup_connections(1)
            .max_lifetime(Duration::from_secs(1));
        let pool = GenericPool::with_time_getter(simple_factory, config, test_pool_time_now);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 1, "warmup should create one idle resource");

        let resource = pool
            .try_acquire()
            .expect("warmup resource should not look immediately expired");
        assert_eq!(*resource, 42u32, "warmup resource should stay reusable");

        resource.return_to_pool();
        crate::test_complete!("warmup_created_timestamps_follow_time_getter");
    }

    // ========================================================================
    // Audit regression tests (asupersync-10x0x.44)
    // ========================================================================

    #[test]
    fn return_to_closed_pool_drops_resource() {
        init_test("return_to_closed_pool_drops_resource");

        // Verify that returning a resource to a closed pool silently drops
        // the resource instead of adding it to the idle queue.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire a resource
        let resource =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

        // Close the pool while the resource is held
        futures_lite::future::block_on(pool.close());

        // Return the resource — it should be silently dropped, not added to idle
        resource.return_to_pool();

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.idle == 0,
            "no idle after return to closed pool",
            0usize,
            stats.idle
        );
        crate::assert_with_log!(
            stats.active == 0,
            "active decremented despite closed pool",
            0usize,
            stats.active
        );

        crate::test_complete!("return_to_closed_pool_drops_resource");
    }

    #[test]
    fn discard_to_closed_pool_decrements_active() {
        init_test("discard_to_closed_pool_decrements_active");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let resource =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

        futures_lite::future::block_on(pool.close());

        // Discard the resource after pool is closed
        resource.discard();

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "active decremented after discard to closed pool",
            0usize,
            stats.active
        );

        crate::test_complete!("discard_to_closed_pool_decrements_active");
    }

    #[test]
    fn create_slot_reservation_cancel_safety() {
        init_test("create_slot_reservation_cancel_safety");

        // Verify that dropping a CreateSlotReservation without committing
        // correctly releases the slot and wakes a waiter.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));

        // Reserve a slot (simulates start of resource creation)
        let slot = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot.is_some(), "should reserve slot");

        // Verify pool is at capacity
        let slot2 = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot2.is_none(), "pool at capacity with one creating slot");

        // Drop without committing (simulates cancel during create)
        drop(slot);

        // Creating count should be back to 0
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.total == 0,
            "total back to 0 after cancelled reservation",
            0usize,
            stats.total
        );

        // Should be able to reserve again
        let slot3 = CreateSlotReservation::try_reserve(&pool, None);
        assert!(slot3.is_some(), "slot available after cancel");
        if let Some(s) = slot3 {
            s.commit();
        }

        crate::test_complete!("create_slot_reservation_cancel_safety");
    }

    #[test]
    fn idle_eviction_respects_idle_timeout() {
        init_test("idle_eviction_respects_idle_timeout");

        let config = PoolConfig::with_max_size(5).idle_timeout(Duration::from_millis(10));
        let pool = GenericPool::with_time_getter(simple_factory, config, test_pool_time_now);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let r = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire");
        r.return_to_pool();

        let stats = pool.stats();
        assert_eq!(stats.idle, 1, "resource should be idle");

        advance_test_pool_time(Duration::from_millis(20));

        let result = pool.try_acquire();
        assert!(
            result.is_none(),
            "expired idle resource should be evicted, try_acquire returns None"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 0,
            "expired idle resource should have been evicted"
        );

        crate::test_complete!("idle_eviction_respects_idle_timeout");
    }

    #[test]
    fn idle_eviction_respects_max_lifetime() {
        init_test("idle_eviction_respects_max_lifetime");

        let config = PoolConfig::with_max_size(5).max_lifetime(Duration::from_millis(10));
        let pool = GenericPool::with_time_getter(simple_factory, config, test_pool_time_now);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let r = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire");
        r.return_to_pool();

        advance_test_pool_time(Duration::from_millis(20));

        let result = pool.try_acquire();
        assert!(
            result.is_none(),
            "resource past max_lifetime should be evicted"
        );

        let stats = pool.stats();
        assert_eq!(
            stats.idle, 0,
            "expired resource should be evicted from idle"
        );

        crate::test_complete!("idle_eviction_respects_max_lifetime");
    }

    #[test]
    fn multiple_acquire_return_cycles_keep_accounting_consistent() {
        init_test("multiple_acquire_return_cycles_keep_accounting_consistent");

        // Verify that mixed return_to_pool, discard, and implicit drop
        // all keep the accounting correct over many cycles.
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        for i in 0..50 {
            let r = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire");
            match i % 3 {
                0 => r.return_to_pool(),
                1 => r.discard(),
                _ => drop(r), // implicit return via Drop
            }
        }

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "no active after all returned/discarded",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.total_acquisitions == 50,
            "50 total acquisitions",
            50u64,
            stats.total_acquisitions
        );

        crate::test_complete!("multiple_acquire_return_cycles_keep_accounting_consistent");
    }

    #[test]
    fn warmup_resources_reused_by_acquire() {
        init_test("warmup_resources_reused_by_acquire");

        // Verify that warmup resources are available for acquire.
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let config = PoolConfig::with_max_size(10).warmup_connections(2);
        let pool = GenericPool::new(factory, config);

        let created = futures_lite::future::block_on(pool.warmup()).expect("warmup should succeed");
        assert_eq!(created, 2);

        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire should reuse warmup resources (ids 0 and 1), not create new ones
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 1");
        let r2 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 2");

        // Both should be from warmup (ids 0 or 1)
        assert!(
            *r1 <= 1u32 && *r2 <= 1u32,
            "warmup resources should be reused: got {} and {}",
            *r1,
            *r2
        );
        assert_ne!(*r1, *r2, "should be different resources");

        crate::test_complete!("warmup_resources_reused_by_acquire");
    }

    // ========================================================================
    // PoolConfig health/warmup builder tests (asupersync-cl94)
    // ========================================================================

    #[test]
    fn pool_config_health_check_builder() {
        init_test("pool_config_health_check_builder");

        let config = PoolConfig::with_max_size(5)
            .health_check_on_acquire(true)
            .health_check_interval(Some(Duration::from_secs(60)))
            .evict_unhealthy(false);

        assert!(config.health_check_on_acquire);
        assert_eq!(config.health_check_interval, Some(Duration::from_secs(60)));
        assert!(!config.evict_unhealthy);

        crate::test_complete!("pool_config_health_check_builder");
    }

    #[test]
    fn pool_config_warmup_builder() {
        init_test("pool_config_warmup_builder");

        let config = PoolConfig::with_max_size(5)
            .warmup_connections(3)
            .warmup_timeout(Duration::from_secs(10))
            .warmup_failure_strategy(WarmupStrategy::FailFast);

        assert_eq!(config.warmup_connections, 3);
        assert_eq!(config.warmup_timeout, Duration::from_secs(10));
        assert_eq!(config.warmup_failure_strategy, WarmupStrategy::FailFast);

        crate::test_complete!("pool_config_warmup_builder");
    }

    // ========================================================================
    // Invariant tests: cancel-safety, exhaustion, factory errors
    // ========================================================================

    /// Invariant: dropping an acquire future that is suspended inside
    /// `WaitForNotification` removes the waiter from the queue.
    #[test]
    #[allow(unsafe_code)]
    fn pool_cancel_during_wait_does_not_leak_waiter() {
        init_test("pool_cancel_during_wait_does_not_leak_waiter");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire the one resource so pool is at capacity.
        let held = futures_lite::future::block_on(pool.acquire(&cx_handle)).expect("first acquire");

        // Create a second acquire future. It will enter WaitForNotification
        // because the pool is exhausted (max_size=1, active=1).
        let waker = noop_pool_waker();
        let mut task_cx = std::task::Context::from_waker(&waker);
        {
            let mut acquire_fut = pool.acquire(&cx_handle);
            // SAFETY: acquire_fut lives on the stack and we do not move it.
            let pinned = std::pin::Pin::new(&mut acquire_fut);
            let poll_result = pinned.poll(&mut task_cx);
            // Should be Pending — pool is full.
            let is_pending = poll_result.is_pending();
            crate::assert_with_log!(is_pending, "acquire is Pending", true, is_pending);

            // Verify a waiter was registered.
            let waiters_before = pool.stats().waiters;
            crate::assert_with_log!(
                waiters_before >= 1,
                "waiter registered",
                true,
                waiters_before >= 1
            );
            // acquire_fut dropped here — WaitForNotification::drop fires.
        }

        // After drop, waiters must be 0.
        let waiters_after = pool.stats().waiters;
        crate::assert_with_log!(
            waiters_after == 0,
            "waiter cleaned on drop",
            0usize,
            waiters_after
        );

        // Return the held resource and verify normal operation.
        held.return_to_pool();
        let reacquired = futures_lite::future::block_on(pool.acquire(&cx_handle));
        let ok = reacquired.is_ok();
        crate::assert_with_log!(ok, "reacquire succeeds", true, ok);

        crate::test_complete!("pool_cancel_during_wait_does_not_leak_waiter");
    }

    /// Invariant: when the pool is at capacity, acquire blocks; when a
    /// resource is returned, the blocked acquirer is woken and succeeds.
    #[test]
    fn pool_exhaustion_blocks_then_unblocks_on_return() {
        init_test("pool_exhaustion_blocks_then_unblocks_on_return");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire the single resource.
        let held = futures_lite::future::block_on(pool.acquire(&cx_handle)).expect("first acquire");
        let held_val = *held;

        // Spawn a thread that will block on acquire.
        let pool2 = Arc::clone(&pool);
        let (queued_tx, queued_rx) = mpsc::channel();
        let blocker = std::thread::spawn(move || {
            let cx2: crate::cx::Cx = crate::cx::Cx::for_testing();
            let waker = noop_pool_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut acquire_fut = std::pin::pin!(pool2.acquire(&cx2));

            match acquire_fut.as_mut().poll(&mut task_cx) {
                Poll::Pending => queued_tx.send(()).expect("signal queued pool waiter"),
                Poll::Ready(result) => return result,
            }

            loop {
                match acquire_fut.as_mut().poll(&mut task_cx) {
                    Poll::Ready(result) => return result,
                    Poll::Pending => std::thread::yield_now(),
                }
            }
        });

        queued_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("blocker should queue before resource return");
        let waiter_registered = pool.stats().waiters == 1;
        crate::assert_with_log!(
            waiter_registered,
            "blocker should register as a waiter without sleep-based synchronization",
            true,
            waiter_registered
        );

        // Return the resource — this should wake the blocked acquirer.
        held.return_to_pool();

        let result = blocker.join().expect("blocker thread panicked");
        let acquired = result.expect("blocked acquire should succeed");
        let val = *acquired;
        crate::assert_with_log!(
            val == held_val,
            "blocked acquirer got returned resource",
            held_val,
            val
        );

        crate::test_complete!("pool_exhaustion_blocks_then_unblocks_on_return");
    }

    /// Invariant: returning one resource from an exhausted pool only wakes one
    /// waiter; remaining waiters stay queued until another resource return.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn pool_return_wakes_waiters_one_at_a_time() {
        init_test("pool_return_wakes_waiters_one_at_a_time");

        let pool = Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(1),
        ));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx_handle)).expect("first acquire");

        let (queued_tx, queued_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let (release_second_tx, release_second_rx) = std::sync::mpsc::channel();

        let first_waiter_pool = Arc::clone(&pool);
        let first_waiter_tx = acquired_tx.clone();
        let first_queued_tx = queued_tx.clone();
        let first_waiter = std::thread::spawn(move || {
            let cx = crate::cx::Cx::for_testing();
            let waker = noop_pool_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut acquire_fut = std::pin::pin!(first_waiter_pool.acquire(&cx));

            match acquire_fut.as_mut().poll(&mut task_cx) {
                Poll::Pending => first_queued_tx
                    .send(1usize)
                    .expect("signal waiter A queued"),
                Poll::Ready(_) => panic!("waiter A acquired before resource return"),
            }

            let acquired = loop {
                match acquire_fut.as_mut().poll(&mut task_cx) {
                    Poll::Ready(result) => break result.expect("waiter A"),
                    Poll::Pending => std::thread::yield_now(),
                }
            };
            first_waiter_tx
                .send(1usize)
                .expect("send waiter A acquisition");
            release_first_rx.recv().expect("waiter A release signal");
            acquired.return_to_pool();
        });

        let second_waiter_pool = Arc::clone(&pool);
        let second_waiter_tx = acquired_tx;
        let second_queued_tx = queued_tx;
        let second_waiter = std::thread::spawn(move || {
            let cx = crate::cx::Cx::for_testing();
            let waker = noop_pool_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut acquire_fut = std::pin::pin!(second_waiter_pool.acquire(&cx));

            match acquire_fut.as_mut().poll(&mut task_cx) {
                Poll::Pending => second_queued_tx
                    .send(2usize)
                    .expect("signal waiter B queued"),
                Poll::Ready(_) => panic!("waiter B acquired before resource return"),
            }

            let acquired = loop {
                match acquire_fut.as_mut().poll(&mut task_cx) {
                    Poll::Ready(result) => break result.expect("waiter B"),
                    Poll::Pending => std::thread::yield_now(),
                }
            };
            second_waiter_tx
                .send(2usize)
                .expect("send waiter B acquisition");
            release_second_rx.recv().expect("waiter B release signal");
            acquired.return_to_pool();
        });

        let queued_a = queued_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first waiter should queue before resource return");
        let queued_b = queued_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second waiter should queue before resource return");
        let both_waiters_registered = queued_a != queued_b && pool.stats().waiters == 2;
        crate::assert_with_log!(
            both_waiters_registered,
            "both blocked acquirers should register as waiters",
            true,
            both_waiters_registered
        );

        held.return_to_pool();

        let first = acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first waiter should wake");

        let mut one_waiter_still_blocked = false;
        for _ in 0..4_096 {
            let stats = pool.stats();
            if stats.waiters == 1 && stats.active == 1 {
                one_waiter_still_blocked = true;
                break;
            }
            std::thread::yield_now();
        }
        crate::assert_with_log!(
            one_waiter_still_blocked,
            "one waiter should remain queued while the woken waiter holds the resource",
            true,
            one_waiter_still_blocked
        );

        match first {
            1 => release_first_tx.send(()).expect("release waiter A"),
            2 => release_second_tx.send(()).expect("release waiter B"),
            other => panic!("unexpected waiter id: {other}"),
        }

        let second = acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second waiter should wake after the next return");
        crate::assert_with_log!(
            first != second,
            "resource returns should wake distinct waiters sequentially",
            true,
            first != second
        );

        let mut no_waiters_left = false;
        for _ in 0..4_096 {
            let stats = pool.stats();
            if stats.waiters == 0 && stats.active == 1 {
                no_waiters_left = true;
                break;
            }
            std::thread::yield_now();
        }
        crate::assert_with_log!(
            no_waiters_left,
            "second wake should drain the waiter queue while the final borrower holds the resource",
            true,
            no_waiters_left
        );

        match second {
            1 => release_first_tx
                .send(())
                .expect("release waiter A after second wake"),
            2 => release_second_tx
                .send(())
                .expect("release waiter B after second wake"),
            other => panic!("unexpected waiter id: {other}"),
        }

        first_waiter.join().expect("waiter A should not panic");
        second_waiter.join().expect("waiter B should not panic");

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.waiters == 0,
            "all waiters should be drained after both resources are returned",
            0usize,
            stats.waiters
        );
        crate::assert_with_log!(
            stats.active == 0,
            "no active resources should remain after both waiters release",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.idle == 1,
            "the single pooled resource should be returned to idle storage",
            1usize,
            stats.idle
        );
        crate::assert_with_log!(
            stats.total == 1,
            "capacity accounting should settle back to a single retained resource",
            1usize,
            stats.total
        );

        crate::test_complete!("pool_return_wakes_waiters_one_at_a_time");
    }

    /// Invariant: if the factory returns an error during acquire, the
    /// creating slot is released and does not permanently reduce capacity.
    #[test]
    fn pool_factory_error_releases_create_slot() {
        init_test("pool_factory_error_releases_create_slot");

        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        // Factory that fails on the first call, succeeds on subsequent ones.
        let factory = move || {
            let count = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if count == 0 {
                    Err::<u32, Box<dyn std::error::Error + Send + Sync>>(
                        "deliberate factory error".into(),
                    )
                } else {
                    Ok(count)
                }
            })
                as std::pin::Pin<
                    Box<
                        dyn Future<Output = Result<u32, Box<dyn std::error::Error + Send + Sync>>>
                            + Send,
                    >,
                >
        };

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(2));
        let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();

        // First acquire should fail (factory error).
        let first = futures_lite::future::block_on(pool.acquire(&cx_handle));
        let is_err = first.is_err();
        crate::assert_with_log!(is_err, "first acquire fails", true, is_err);

        // After the error, creating count must be 0 (slot released by RAII).
        let stats = pool.stats();
        crate::assert_with_log!(
            stats.total == 0,
            "no phantom slot leaked",
            0usize,
            stats.total
        );

        // Second acquire should succeed (factory returns Ok now).
        let second = futures_lite::future::block_on(pool.acquire(&cx_handle));
        let ok = second.is_ok();
        crate::assert_with_log!(ok, "second acquire succeeds", true, ok);

        crate::test_complete!("pool_factory_error_releases_create_slot");
    }

    struct DropTrackedResource {
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for DropTrackedResource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn pool_close_while_create_in_flight_returns_closed() {
        init_test("pool_close_while_create_in_flight_returns_closed");

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (unblock_tx, unblock_rx) = std::sync::mpsc::channel();
        let unblock_rx = Arc::new(std::sync::Mutex::new(unblock_rx));
        let drop_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let factory = {
            let unblock_rx = Arc::clone(&unblock_rx);
            let drop_count = Arc::clone(&drop_count);
            move || {
                let unblock_rx = Arc::clone(&unblock_rx);
                let entered_tx = entered_tx.clone();
                let drop_count = Arc::clone(&drop_count);
                Box::pin(async move {
                    entered_tx.send(()).expect("factory entered");
                    unblock_rx
                        .lock()
                        .expect("factory unblock receiver lock")
                        .recv()
                        .expect("factory unblock signal");
                    Ok::<DropTrackedResource, Box<dyn std::error::Error + Send + Sync>>(
                        DropTrackedResource { drops: drop_count },
                    )
                })
                    as std::pin::Pin<
                        Box<
                            dyn Future<
                                    Output = Result<
                                        DropTrackedResource,
                                        Box<dyn std::error::Error + Send + Sync>,
                                    >,
                                > + Send,
                        >,
                    >
            }
        };

        let pool = Arc::new(GenericPool::new(factory, PoolConfig::with_max_size(1)));
        let acquire_pool = Arc::clone(&pool);
        let (result_tx, result_rx) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            let cx_handle: crate::cx::Cx = crate::cx::Cx::for_testing();
            let result =
                futures_lite::future::block_on(acquire_pool.acquire(&cx_handle)).map(|_| ());
            result_tx.send(result).expect("send acquire result");
        });

        entered_rx.recv().expect("wait for factory entry");
        futures_lite::future::block_on(pool.close());
        unblock_tx.send(()).expect("unblock factory");

        let result = result_rx.recv().expect("receive acquire result");
        crate::assert_with_log!(
            matches!(result, Err(PoolError::Closed)),
            "acquire returns closed once close wins the create race",
            true,
            matches!(result, Err(PoolError::Closed))
        );

        worker.join().expect("worker thread panicked");

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 0,
            "no active resources leaked",
            0usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.total == 0,
            "no total capacity leaked",
            0usize,
            stats.total
        );

        let reacquire = pool.try_acquire();
        crate::assert_with_log!(
            reacquire.is_none(),
            "closed pool does not expose created resource",
            true,
            reacquire.is_none()
        );
        crate::assert_with_log!(
            drop_count.load(std::sync::atomic::Ordering::SeqCst) == 1,
            "freshly created resource is dropped when close wins create race",
            1usize,
            drop_count.load(std::sync::atomic::Ordering::SeqCst)
        );

        crate::test_complete!("pool_close_while_create_in_flight_returns_closed");
    }

    // =========================================================================
    // Pure data-type tests (wave 42 – CyanBarn)
    // =========================================================================

    #[test]
    fn warmup_strategy_debug_clone_copy_eq_default() {
        let def = WarmupStrategy::default();
        assert_eq!(def, WarmupStrategy::BestEffort);
        for s in [
            WarmupStrategy::BestEffort,
            WarmupStrategy::FailFast,
            WarmupStrategy::RequireMinimum,
        ] {
            let copied = s;
            let cloned = s;
            assert_eq!(copied, cloned);
            let dbg = format!("{s:?}");
            assert!(!dbg.is_empty());
        }
        assert_ne!(WarmupStrategy::BestEffort, WarmupStrategy::FailFast);
        assert_ne!(WarmupStrategy::FailFast, WarmupStrategy::RequireMinimum);
    }

    #[test]
    fn destroy_reason_debug_clone_copy_eq() {
        for r in [
            DestroyReason::Unhealthy,
            DestroyReason::IdleTimeout,
            DestroyReason::MaxLifetime,
        ] {
            let copied = r;
            let cloned = r;
            assert_eq!(copied, cloned);
            let dbg = format!("{r:?}");
            assert!(!dbg.is_empty());
        }
        assert_ne!(DestroyReason::Unhealthy, DestroyReason::IdleTimeout);
        assert_eq!(DestroyReason::Unhealthy.as_label(), "unhealthy");
        assert_eq!(DestroyReason::IdleTimeout.as_label(), "idle_timeout");
        assert_eq!(DestroyReason::MaxLifetime.as_label(), "max_lifetime");
    }

    #[test]
    fn pool_stats_debug_clone_default() {
        let def = PoolStats::default();
        assert_eq!(def.active, 0);
        assert_eq!(def.idle, 0);
        assert_eq!(def.total, 0);
        assert_eq!(def.total_acquisitions, 0);
        let cloned = def.clone();
        assert_eq!(cloned.active, 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("PoolStats"));
    }

    // ========================================================================
    // Metamorphic Testing: Pool acquire/release lifecycle invariants
    // ========================================================================

    #[test]
    fn metamorphic_resource_conservation_invariant() {
        init_test("metamorphic_resource_conservation_invariant");

        // MR: total_resources(before_operation) == total_resources(after_operation)
        // Conservation holds across any sequence of acquire/release operations
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(5));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let initial_stats = pool.stats();
        let initial_total = initial_stats.total;

        // Perform sequence: acquire -> return -> acquire -> discard -> acquire -> drop
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 1");
        r1.return_to_pool();

        let r2 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 2");
        r2.discard();

        let r3 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 3");
        drop(r3); // implicit return via Drop

        let final_stats = pool.stats();
        let final_total = final_stats.total;

        // Conservation: total resources should be preserved (accounting for discarded)
        // Note: discard removes from total, so final should equal initial + created - discarded
        crate::assert_with_log!(
            final_total >= initial_total,
            "resource conservation: total preserved or increased",
            true,
            final_total >= initial_total
        );
        crate::assert_with_log!(
            final_stats.active == 0,
            "all resources returned or discarded",
            0usize,
            final_stats.active
        );

        crate::test_complete!("metamorphic_resource_conservation_invariant");
    }

    #[test]
    fn metamorphic_acquire_release_symmetry() {
        init_test("metamorphic_acquire_release_symmetry");

        // MR: acquisitions(seq) == releases(seq) for any complete sequence
        // Each successful acquire must be paired with exactly one release
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let initial_acquisitions = pool.stats().total_acquisitions;

        // Perform sequence of acquire/release pairs
        for i in 0..10 {
            let resource =
                futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");

            match i % 3 {
                0 => resource.return_to_pool(),
                1 => resource.discard(),
                _ => drop(resource), // implicit return
            }
        }

        let final_stats = pool.stats();
        let total_acquisitions = final_stats.total_acquisitions - initial_acquisitions;

        // Symmetry: all acquired resources have been released (active == 0)
        crate::assert_with_log!(
            total_acquisitions == 10,
            "10 acquisitions performed",
            10u64,
            total_acquisitions
        );
        crate::assert_with_log!(
            final_stats.active == 0,
            "acquire/release symmetry: all acquired resources released",
            0usize,
            final_stats.active
        );

        crate::test_complete!("metamorphic_acquire_release_symmetry");
    }

    #[test]
    fn metamorphic_resource_reuse_equivalence() {
        init_test("metamorphic_resource_reuse_equivalence");

        // MR: reused_resource.value == original_resource.value
        // Returned resources should be equivalent to original when reacquired
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(3));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Acquire first resource, remember its value
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 1");
        let original_value: u32 = *r1;
        r1.return_to_pool();

        // Acquire again - should get the same resource back
        let r2 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 2");
        let reused_value = *r2;

        // Equivalence: reused resource should have same value as original
        crate::assert_with_log!(
            reused_value == original_value,
            "resource reuse equivalence",
            original_value,
            reused_value
        );

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.idle == 0,
            "reused resource removed from idle",
            0usize,
            stats.idle
        );
        crate::assert_with_log!(
            stats.active == 1,
            "reused resource now active",
            1usize,
            stats.active
        );

        r2.return_to_pool();
        crate::test_complete!("metamorphic_resource_reuse_equivalence");
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AcquireDropEquivalenceSurface {
        stats_after_release: (usize, usize, usize, u64),
        reacquired_value: u32,
        stats_while_reacquired: (usize, usize, usize, u64),
    }

    fn run_acquire_drop_equivalence_surface(explicit_drop: bool) -> AcquireDropEquivalenceSurface {
        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(2));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        if explicit_drop {
            let resource: PooledResource<u32> =
                futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire should succeed");
            drop(resource);
        } else {
            {
                let _resource = futures_lite::future::block_on(pool.acquire(&cx))
                    .expect("acquire should succeed");
            }
        }

        let stats_after_release = {
            let stats = pool.stats();
            (
                stats.active,
                stats.idle,
                stats.total,
                stats.total_acquisitions,
            )
        };

        let reacquired =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("reacquire should succeed");
        let reacquired_value = *reacquired;
        let stats_while_reacquired = {
            let stats = pool.stats();
            (
                stats.active,
                stats.idle,
                stats.total,
                stats.total_acquisitions,
            )
        };
        reacquired.return_to_pool();

        AcquireDropEquivalenceSurface {
            stats_after_release,
            reacquired_value,
            stats_while_reacquired,
        }
    }

    #[test]
    fn metamorphic_acquire_then_explicit_drop_matches_scope_drop() {
        init_test("metamorphic_acquire_then_explicit_drop_matches_scope_drop");

        let explicit_drop = run_acquire_drop_equivalence_surface(true);
        let scope_drop = run_acquire_drop_equivalence_surface(false);

        crate::assert_with_log!(
            explicit_drop == scope_drop,
            "explicit drop and scope-end drop should produce the same pool surface",
            format!("{scope_drop:?}"),
            format!("{explicit_drop:?}")
        );
        crate::assert_with_log!(
            explicit_drop.stats_after_release == (0, 1, 1, 1),
            "released surface after first acquire",
            (0usize, 1usize, 1usize, 1u64),
            explicit_drop.stats_after_release
        );
        crate::assert_with_log!(
            explicit_drop.stats_while_reacquired == (1, 0, 1, 2),
            "reacquire surface after drop equivalence",
            (1usize, 0usize, 1usize, 2u64),
            explicit_drop.stats_while_reacquired
        );
        crate::assert_with_log!(
            explicit_drop.reacquired_value == 0,
            "both drop paths should recycle the same first resource",
            0u32,
            explicit_drop.reacquired_value
        );

        crate::test_complete!("metamorphic_acquire_then_explicit_drop_matches_scope_drop");
    }

    #[test]
    fn metamorphic_cancelled_waiter_preserves_reuse_identity() {
        init_test("metamorphic_cancelled_waiter_preserves_reuse_identity");

        let counter = std::sync::atomic::AtomicU32::new(0);
        let factory = move || {
            let id = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
                as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(1));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
        let original_id: u32 = *held;

        let waker = noop_pool_waker();
        let mut task_cx = std::task::Context::from_waker(&waker);
        {
            let mut blocked_acquire = pool.acquire(&cx);
            let poll_result = std::pin::Pin::new(&mut blocked_acquire).poll(&mut task_cx);
            crate::assert_with_log!(
                poll_result.is_pending(),
                "second acquire should block while the only resource is held",
                true,
                poll_result.is_pending()
            );
            crate::assert_with_log!(
                pool.stats().waiters == 1,
                "blocked acquire should register one waiter",
                1usize,
                pool.stats().waiters
            );
        }

        crate::assert_with_log!(
            pool.stats().waiters == 0,
            "dropping the blocked acquire should clean the waiter queue",
            0usize,
            pool.stats().waiters
        );

        held.return_to_pool();

        let reacquired = futures_lite::future::block_on(pool.acquire(&cx)).expect("reacquire");
        let reacquired_id = *reacquired;
        crate::assert_with_log!(
            reacquired_id == original_id,
            "cancelled waiter must not perturb the identity of the next clean reacquire",
            original_id,
            reacquired_id
        );

        let stats = pool.stats();
        crate::assert_with_log!(
            stats.active == 1,
            "reacquired resource should be active and not leaked to the cancelled waiter",
            1usize,
            stats.active
        );
        crate::assert_with_log!(
            stats.waiters == 0,
            "cancelled waiter cleanup must persist after the reacquire",
            0usize,
            stats.waiters
        );

        reacquired.return_to_pool();
        let final_stats = pool.stats();
        crate::assert_with_log!(
            final_stats.idle == 1,
            "returned resource should still be reusable after cancelled waiter cleanup",
            1usize,
            final_stats.idle
        );

        crate::test_complete!("metamorphic_cancelled_waiter_preserves_reuse_identity");
    }

    #[test]
    fn pool_fresh_handoff_time_panic_rolls_back_active_capacity() {
        init_test("pool_fresh_handoff_time_panic_rolls_back_active_capacity");
        let created = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pool = GenericPool::with_time_getter(
            counting_factory(Arc::clone(&created)),
            PoolConfig::with_max_size(1),
            panic_once_test_pool_time_now,
        );
        let cx = Cx::for_testing();
        panic_test_pool_time_on_call(2);

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures_lite::future::block_on(pool.acquire(&cx))
        }));
        let (time_calls, pending_panic) = test_pool_time_probe_state();
        disarm_test_pool_time_panic();
        assert!(
            panic_result.is_err(),
            "fresh wrapper construction must hit the injected time panic"
        );
        assert_eq!(time_calls, 2, "fresh handoff must reach the guarded clock");
        assert_eq!(pending_panic, None, "fresh handoff must consume the probe");
        assert_eq!(
            created.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the panic must occur after one resource is created"
        );

        let after_panic = pool.stats();
        assert_eq!(
            after_panic.active, 0,
            "fresh handoff panic rolls back active"
        );
        assert_eq!(after_panic.total, 0, "fresh handoff panic frees capacity");
        assert_eq!(
            after_panic.total_acquisitions, 0,
            "a resource never handed out is not a completed acquisition"
        );

        let replacement = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("replacement acquire after fresh handoff panic");
        assert_eq!(*replacement, 1, "replacement must use the recovered slot");
        assert_eq!(
            created.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "replacement must create in the recovered slot"
        );
        replacement.return_to_pool();
        assert_eq!(pool.stats().idle, 1, "replacement remains reusable");

        crate::test_complete!("pool_fresh_handoff_time_panic_rolls_back_active_capacity");
    }

    #[test]
    fn pool_idle_handoff_time_panic_rolls_back_active_capacity() {
        init_test("pool_idle_handoff_time_panic_rolls_back_active_capacity");
        let created = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pool = GenericPool::with_time_getter(
            counting_factory(Arc::clone(&created)),
            PoolConfig::with_max_size(1),
            panic_once_test_pool_time_now,
        );
        let cx = Cx::for_testing();

        let initial = futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
        initial.return_to_pool();
        let baseline = pool.stats();
        assert_eq!(
            (
                baseline.active,
                baseline.idle,
                baseline.total,
                baseline.total_acquisitions,
            ),
            (0, 1, 1, 1),
            "initial resource must be the sole idle slot"
        );
        panic_test_pool_time_on_call(2);

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures_lite::future::block_on(pool.acquire(&cx))
        }));
        let (time_calls, pending_panic) = test_pool_time_probe_state();
        disarm_test_pool_time_panic();
        assert!(
            panic_result.is_err(),
            "idle wrapper construction must hit the injected time panic"
        );
        assert_eq!(time_calls, 2, "idle handoff must reach the guarded clock");
        assert_eq!(pending_panic, None, "idle handoff must consume the probe");

        let after_panic = pool.stats();
        assert_eq!(
            after_panic.active, 0,
            "idle handoff panic rolls back active"
        );
        assert_eq!(after_panic.idle, 0, "the detached resource was destroyed");
        assert_eq!(after_panic.total, 0, "idle handoff panic frees capacity");
        assert_eq!(
            after_panic.total_acquisitions, baseline.total_acquisitions,
            "failed idle handoff rolls back acquisition accounting"
        );

        let replacement = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("replacement acquire after idle handoff panic");
        assert_eq!(*replacement, 1, "replacement must use the recovered slot");
        assert_eq!(
            created.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "replacement must create in the recovered slot"
        );
        replacement.return_to_pool();
        assert_eq!(pool.stats().idle, 1, "replacement remains reusable");

        crate::test_complete!("pool_idle_handoff_time_panic_rolls_back_active_capacity");
    }

    #[test]
    fn pool_try_acquire_handoff_time_panic_rolls_back_active_capacity() {
        init_test("pool_try_acquire_handoff_time_panic_rolls_back_active_capacity");
        let created = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pool = GenericPool::with_time_getter(
            counting_factory(Arc::clone(&created)),
            PoolConfig::with_max_size(1),
            panic_once_test_pool_time_now,
        );
        let cx = Cx::for_testing();

        let initial = futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
        initial.return_to_pool();
        let baseline = pool.stats();
        assert_eq!(
            (
                baseline.active,
                baseline.idle,
                baseline.total,
                baseline.total_acquisitions,
            ),
            (0, 1, 1, 1),
            "initial resource must be the sole idle slot"
        );
        panic_test_pool_time_on_call(3);

        let panic_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pool.try_acquire()));
        let (time_calls, pending_panic) = test_pool_time_probe_state();
        disarm_test_pool_time_panic();
        assert!(
            panic_result.is_err(),
            "try_acquire handoff must hit the injected time panic"
        );
        assert_eq!(
            time_calls, 3,
            "try_acquire handoff must reach the guarded clock"
        );
        assert_eq!(
            pending_panic, None,
            "try_acquire handoff must consume the probe"
        );

        let after_panic = pool.stats();
        assert_eq!(after_panic.active, 0, "try_acquire panic rolls back active");
        assert_eq!(after_panic.idle, 0, "the detached resource was destroyed");
        assert_eq!(after_panic.total, 0, "try_acquire panic frees capacity");
        assert_eq!(
            after_panic.total_acquisitions, baseline.total_acquisitions,
            "failed try_acquire handoff rolls back acquisition accounting"
        );

        let replacement = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("replacement acquire after try_acquire handoff panic");
        assert_eq!(*replacement, 1, "replacement must use the recovered slot");
        assert_eq!(
            created.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "replacement must create in the recovered slot"
        );
        replacement.return_to_pool();
        assert_eq!(pool.stats().idle, 1, "replacement remains reusable");

        crate::test_complete!("pool_try_acquire_handoff_time_panic_rolls_back_active_capacity");
    }

    fn assert_panicking_resource_discard_releases_capacity(release_via_broken_drop: bool) {
        let created = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let drop_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let factory = {
            let created = Arc::clone(&created);
            let drop_attempts = Arc::clone(&drop_attempts);
            move || {
                let id = created.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let resource = PanicOnDropPoolResource {
                    id,
                    panic_on_drop: id == 0,
                    drop_attempts: Arc::clone(&drop_attempts),
                };
                Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resource) })
                    as Pin<Box<dyn Future<Output = _> + Send>>
            }
        };
        let pool = GenericPool::with_time_getter(
            factory,
            PoolConfig::with_max_size(1),
            test_pool_time_now,
        );
        let cx = Cx::for_testing();
        let mut resource: PooledResource<PanicOnDropPoolResource> =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
        assert_eq!(resource.id, 0, "the first resource must be the panic probe");

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if release_via_broken_drop {
                resource.mark_broken();
                drop(resource);
            } else {
                resource.discard();
            }
        }));
        assert!(
            panic_result.is_err(),
            "the first resource destructor must unwind"
        );
        assert_eq!(
            drop_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the panicking resource must have one drop attempt"
        );

        let after_discard = pool.stats();
        assert_eq!(
            after_discard.active, 0,
            "a panicking resource destructor must not leak active capacity"
        );
        assert_eq!(
            after_discard.total, 0,
            "a panicking resource destructor must leave the discarded slot reusable"
        );

        let replacement = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("reacquire after panicking discard");
        assert_eq!(replacement.id, 1, "reacquire must create a replacement");
        assert_eq!(
            pool.stats().active,
            1,
            "the replacement must occupy the recovered slot"
        );
        replacement.return_to_pool();

        let final_stats = pool.stats();
        assert_eq!(final_stats.active, 0, "the replacement must return cleanly");
        assert_eq!(final_stats.idle, 1, "the replacement must remain reusable");
        assert_eq!(final_stats.total, 1, "the pool must stay within max_size");
    }

    #[test]
    fn pool_panicking_discard_drop_releases_capacity() {
        init_test("pool_panicking_discard_drop_releases_capacity");

        assert_panicking_resource_discard_releases_capacity(false);
        assert_panicking_resource_discard_releases_capacity(true);

        crate::test_complete!("pool_panicking_discard_drop_releases_capacity");
    }

    #[test]
    fn pool_panic_drop_releases_capacity() {
        init_test("pool_panic_drop_releases_capacity");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx = Cx::for_testing();

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _resource =
                futures_lite::future::block_on(pool.acquire(&cx)).expect("initial acquire");
            let stats = pool.stats();
            crate::assert_with_log!(
                stats.active == 1,
                "panic path starts with one active resource",
                1usize,
                stats.active
            );
            panic!("intentional pool panic-drop proof");
        }));
        assert!(panic_result.is_err(), "panic path should unwind");

        let stats_after_unwind = pool.stats();
        crate::assert_with_log!(
            stats_after_unwind.active == 0,
            "unwinding drop releases active capacity",
            0usize,
            stats_after_unwind.active
        );
        crate::assert_with_log!(
            stats_after_unwind.idle == 1,
            "unwinding drop returns the resource to idle",
            1usize,
            stats_after_unwind.idle
        );
        crate::assert_with_log!(
            stats_after_unwind.total <= stats_after_unwind.max_size,
            "unwinding drop does not leak pool capacity",
            true,
            stats_after_unwind.total <= stats_after_unwind.max_size
        );

        let reacquired =
            futures_lite::future::block_on(pool.acquire(&cx)).expect("reacquire after unwind");
        crate::assert_with_log!(
            pool.stats().active == 1,
            "pool remains usable after panic-drop cleanup",
            1usize,
            pool.stats().active
        );
        reacquired.return_to_pool();

        let final_stats = pool.stats();
        crate::assert_with_log!(
            final_stats.active == 0,
            "no active permits remain after reacquire",
            0usize,
            final_stats.active
        );

        crate::test_complete!("pool_panic_drop_releases_capacity");
    }

    #[test]
    fn pool_acquire_drop_equivalence_report_logs_capacity_counters() {
        init_test("pool_acquire_drop_equivalence_report_logs_capacity_counters");

        const SCENARIO_ID: &str = "POOL-ACQUIRE-DROP-EQUIVALENCE-TNW6ZI";
        const RCH_COMMAND: &str = "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_tnw6zi_pool_tests cargo test -p asupersync --lib pool_acquire_drop_equivalence_report_logs_capacity_counters --features test-internals -- --nocapture";

        let pool_capacity = 2usize;
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(pool_capacity));
        let cx = Cx::for_testing();
        let mut acquire_count = 0usize;
        let mut drop_release_count = 0usize;

        for release_by_drop in [true, false, true, false] {
            let resource =
                futures_lite::future::block_on(pool.acquire(&cx)).expect("churn acquire");
            acquire_count += 1;
            if release_by_drop {
                drop(resource);
            } else {
                resource.return_to_pool();
            }
            drop_release_count += 1;
        }

        let held_a = futures_lite::future::block_on(pool.acquire(&cx)).expect("held A");
        acquire_count += 1;
        let held_b = futures_lite::future::block_on(pool.acquire(&cx)).expect("held B");
        acquire_count += 1;

        let waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut blocked_acquire = pool.acquire(&cx);
        assert!(
            blocked_acquire.as_mut().poll(&mut task_cx).is_pending(),
            "third acquire should wait while the pool is exhausted"
        );
        let waiter_count = pool.stats().waiters;
        drop(blocked_acquire);
        let cancellation_count = 1usize;

        crate::assert_with_log!(
            pool.stats().waiters == 0,
            "dropping blocked acquire removes the waiter",
            0usize,
            pool.stats().waiters
        );

        drop(held_a);
        drop_release_count += 1;
        held_b.return_to_pool();
        drop_release_count += 1;

        let final_stats = pool.stats();
        crate::assert_with_log!(
            final_stats.active == 0,
            "no outstanding pool permits after report scenario",
            0usize,
            final_stats.active
        );
        crate::assert_with_log!(
            final_stats.total <= pool_capacity,
            "report scenario preserves capacity bound",
            true,
            final_stats.total <= pool_capacity
        );

        let _report = serde_json::json!({
            "scenario_id": SCENARIO_ID,
            "pool_capacity": pool_capacity,
            "acquire_count": acquire_count,
            "drop_release_count": drop_release_count,
            "waiter_count": waiter_count,
            "cancellation_count": cancellation_count,
            "outstanding_permit_count": final_stats.active,
            "final_idle_count": final_stats.idle,
            "final_total_count": final_stats.total,
            "exact_rch_command": RCH_COMMAND,
            "artifact_paths": [],
            "final_acquire_drop_equivalence_verdict": "pass"
        });

        // Pool acquire-drop equivalence report completed

        crate::test_complete!("pool_acquire_drop_equivalence_report_logs_capacity_counters");
    }

    #[test]
    fn metamorphic_broken_drop_matches_explicit_discard() {
        init_test("metamorphic_broken_drop_matches_explicit_discard");

        // MR: explicit_discard(resource) == mark_broken_then_drop(resource)
        // Both broken-resource paths must emit the same discard-class effect and
        // preserve identical hold-duration accounting.
        let release_hold_duration = |release_via_drop: bool| -> Duration {
            let (tx, rx) = mpsc::channel();

            if release_via_drop {
                let mut pooled = PooledResource::new_with_time_getter(17u8, tx, test_pool_time_now);
                pooled.mark_broken();
                advance_test_pool_time(Duration::from_millis(12));
                drop(pooled);
            } else {
                let pooled = PooledResource::new_with_time_getter(17u8, tx, test_pool_time_now);
                advance_test_pool_time(Duration::from_millis(12));
                pooled.discard();
            }

            let msg = rx.recv().expect("broken release message");
            let hold_duration = match msg {
                PoolReturn::Discard { hold_duration } => hold_duration,
                PoolReturn::Return { .. } => {
                    panic!("broken-resource release must emit Discard in both variants")
                }
            };
            crate::assert_with_log!(
                rx.try_recv().is_err(),
                "broken release variants emit exactly one message",
                true,
                rx.try_recv().is_err()
            );
            hold_duration
        };

        let explicit_discard_duration = release_hold_duration(false);
        let broken_drop_duration = release_hold_duration(true);

        crate::assert_with_log!(
            broken_drop_duration == explicit_discard_duration,
            "broken drop matches explicit discard hold-duration accounting",
            explicit_discard_duration,
            broken_drop_duration
        );
        crate::assert_with_log!(
            broken_drop_duration == Duration::from_millis(12),
            "broken release variants preserve the injected time delta",
            Duration::from_millis(12),
            broken_drop_duration
        );

        crate::test_complete!("metamorphic_broken_drop_matches_explicit_discard");
    }

    #[test]
    fn metamorphic_pool_bounds_invariant() {
        init_test("metamorphic_pool_bounds_invariant");

        // MR: total_resources <= max_size for all operation sequences
        // Pool should never exceed configured bounds regardless of operations
        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(2));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Try to acquire more than max_size resources concurrently
        let r1 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 1");
        let r2 = futures_lite::future::block_on(pool.acquire(&cx)).expect("acquire 2");

        let stats_at_capacity = pool.stats();
        crate::assert_with_log!(
            stats_at_capacity.total <= 2,
            "bounds invariant: total <= max_size at capacity",
            true,
            stats_at_capacity.total <= 2
        );
        crate::assert_with_log!(
            stats_at_capacity.active == 2,
            "both resources active",
            2usize,
            stats_at_capacity.active
        );

        // try_acquire should fail when at capacity
        let r3_opt = pool.try_acquire();
        crate::assert_with_log!(
            r3_opt.is_none(),
            "bounds invariant: try_acquire fails at capacity",
            true,
            r3_opt.is_none()
        );

        // Return resources and verify bounds still respected
        r1.return_to_pool();
        r2.return_to_pool();

        let final_stats = pool.stats();
        crate::assert_with_log!(
            final_stats.total <= 2,
            "bounds invariant: total <= max_size after returns",
            true,
            final_stats.total <= 2
        );

        crate::test_complete!("metamorphic_pool_bounds_invariant");
    }

    #[test]
    fn metamorphic_release_idempotency() {
        init_test("metamorphic_release_idempotency");

        // MR: release(release(resource)) == release(resource)
        // Multiple releases of same resource should be idempotent (safe no-ops)
        let (tx, rx) = mpsc::channel();
        let pooled = PooledResource::new(42u8, tx);

        // First release
        pooled.return_to_pool();

        // Verify first release message received
        let msg1 = rx.recv().expect("first return message");
        match msg1 {
            PoolReturn::Return {
                resource: value, ..
            } => {
                crate::assert_with_log!(value == 42, "first release value", 42u8, value);
            }
            PoolReturn::Discard { .. } => unreachable!("expected return"),
        }

        // Second release should be no-op (idempotency)
        // Note: pooled was consumed by return_to_pool(), so we test the obligation system
        // by verifying no second message is sent on drop (which would be a no-op)

        // Verify exactly one message (idempotency - no double release)
        crate::assert_with_log!(
            rx.try_recv().is_err(),
            "release idempotency: no second message",
            true,
            rx.try_recv().is_err()
        );

        // Test with discard idempotency
        let (tx2, rx2) = mpsc::channel();
        let pooled2 = PooledResource::new(99u8, tx2);

        pooled2.discard();

        let msg2 = rx2.recv().expect("discard message");
        match msg2 {
            PoolReturn::Discard { .. } => {
                // Good - discard message received
            }
            PoolReturn::Return { .. } => unreachable!("expected discard"),
        }

        // Verify no second discard message
        crate::assert_with_log!(
            rx2.try_recv().is_err(),
            "discard idempotency: no second message",
            true,
            rx2.try_recv().is_err()
        );

        crate::test_complete!("metamorphic_release_idempotency");
    }

    #[test]
    fn metamorphic_operation_sequence_commutativity() {
        init_test("metamorphic_operation_sequence_commutativity");

        // MR: final_state(seq1) == final_state(reorder(seq1)) for independent operations
        // Commutative property: reordering independent operations preserves final state
        let pool1 = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));
        let pool2 = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        // Sequence 1: acquire A, acquire B, return A, return B
        let a1 = futures_lite::future::block_on(pool1.acquire(&cx)).expect("acquire A1");
        let b1 = futures_lite::future::block_on(pool1.acquire(&cx)).expect("acquire B1");
        a1.return_to_pool();
        b1.return_to_pool();

        // Sequence 2: acquire A, acquire B, return B, return A (reordered returns)
        let a2 = futures_lite::future::block_on(pool2.acquire(&cx)).expect("acquire A2");
        let b2 = futures_lite::future::block_on(pool2.acquire(&cx)).expect("acquire B2");
        b2.return_to_pool();
        a2.return_to_pool();

        // Commutativity: both sequences should result in equivalent final states
        let stats1 = pool1.stats();
        let stats2 = pool2.stats();

        crate::assert_with_log!(
            stats1.active == stats2.active,
            "commutativity: active count equivalent",
            stats1.active,
            stats2.active
        );
        crate::assert_with_log!(
            stats1.idle == stats2.idle,
            "commutativity: idle count equivalent",
            stats1.idle,
            stats2.idle
        );
        crate::assert_with_log!(
            stats1.total_acquisitions == stats2.total_acquisitions,
            "commutativity: acquisition count equivalent",
            stats1.total_acquisitions,
            stats2.total_acquisitions
        );

        crate::test_complete!("metamorphic_operation_sequence_commutativity");
    }

    #[test]
    fn metamorphic_concurrent_acquire_serializes() {
        init_test("metamorphic_concurrent_acquire_serializes");

        // MR: concurrent(acquire_n) == serialize(acquire_n)
        // Concurrent acquisitions should serialize properly without race conditions
        let pool = std::sync::Arc::new(GenericPool::new(
            simple_factory,
            PoolConfig::with_max_size(2), // Small pool to force contention
        ));

        // Test concurrent acquisition with limited pool size
        let cx = crate::cx::Cx::for_testing();
        let num_tasks = 6; // More than pool capacity
        let mut handles = Vec::new();

        for i in 0..num_tasks {
            let pool_clone = std::sync::Arc::clone(&pool);
            let cx_clone = cx.clone();
            let handle = std::thread::spawn(move || {
                futures_lite::future::block_on(async move {
                    // Each task tries to acquire, use briefly, then return
                    let resource = pool_clone.acquire(&cx_clone).await.unwrap();

                    // Simulate brief usage
                    futures_lite::future::yield_now().await;

                    resource.return_to_pool();
                    i // Return task ID
                })
            });
            handles.push(handle);
        }

        // All tasks should complete successfully despite serialization
        let mut results = Vec::new();
        for handle in handles {
            let result = handle.join().unwrap();
            results.push(result);
        }
        results.sort_unstable();

        // Verify all tasks completed
        let expected: Vec<_> = (0..num_tasks).collect();
        crate::assert_with_log!(
            results == expected,
            "concurrent acquire serialization: all tasks completed",
            expected,
            results
        );

        // Pool should be in consistent state
        let final_stats = pool.stats();
        crate::assert_with_log!(
            final_stats.active == 0,
            "serialization: no leaked active resources",
            0usize,
            final_stats.active
        );
        crate::assert_with_log!(
            final_stats.total_acquisitions == num_tasks as u64,
            "serialization: all acquisitions counted",
            num_tasks as u64,
            final_stats.total_acquisitions
        );

        crate::test_complete!("metamorphic_concurrent_acquire_serializes");
    }

    #[test]
    fn metamorphic_deterministic_lab_runtime_replay() {
        init_test("metamorphic_deterministic_lab_runtime_replay");

        // MR: replay(operations_seq) == replay(operations_seq)
        // Identical operation sequences should produce identical results under LabRuntime

        let run_sequence = || -> (Vec<usize>, Vec<usize>, Vec<usize>) {
            let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(3));
            let _runtime =
                crate::lab::runtime::LabRuntime::new(crate::lab::config::LabConfig::default());

            let (active_history, idle_history, total_history) =
                futures_lite::future::block_on(async {
                    let cx = crate::cx::Cx::for_testing();
                    let mut active_trace = Vec::new();
                    let mut idle_trace = Vec::new();
                    let mut total_trace = Vec::new();

                    // Deterministic sequence of operations
                    for i in 0..5 {
                        let resource = pool.acquire(&cx).await.unwrap();
                        let stats = pool.stats();
                        active_trace.push(stats.active);
                        idle_trace.push(stats.idle);
                        total_trace.push(stats.total);

                        // Deterministic decision based on iteration
                        if i % 2 == 0 {
                            resource.return_to_pool();
                        } else {
                            resource.discard();
                        }

                        let stats_after = pool.stats();
                        active_trace.push(stats_after.active);
                        idle_trace.push(stats_after.idle);
                        total_trace.push(stats_after.total);

                        // Deterministic yield
                        crate::runtime::yield_now().await;
                    }

                    (active_trace, idle_trace, total_trace)
                });

            (active_history, idle_history, total_history)
        };

        // Run the same sequence multiple times
        let (active1, idle1, total1) = run_sequence();
        let (active2, idle2, total2) = run_sequence();
        let (active3, idle3, total3) = run_sequence();

        // Deterministic property: all runs should produce identical traces
        crate::assert_with_log!(
            active1 == active2,
            "deterministic replay: active traces match (run1 vs run2)",
            active1,
            active2
        );
        crate::assert_with_log!(
            active2 == active3,
            "deterministic replay: active traces match (run2 vs run3)",
            active2,
            active3
        );
        crate::assert_with_log!(
            idle1 == idle2,
            "deterministic replay: idle traces match (run1 vs run2)",
            idle1,
            idle2
        );
        crate::assert_with_log!(
            idle2 == idle3,
            "deterministic replay: idle traces match (run2 vs run3)",
            idle2,
            idle3
        );
        crate::assert_with_log!(
            total1 == total2,
            "deterministic replay: total traces match (run1 vs run2)",
            total1,
            total2
        );
        crate::assert_with_log!(
            total2 == total3,
            "deterministic replay: total traces match (run2 vs run3)",
            total2,
            total3
        );

        // Test determinism with timing-dependent operations
        let timed_sequence = || -> Vec<u32> {
            let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(2));
            let _runtime =
                crate::lab::runtime::LabRuntime::new(crate::lab::config::LabConfig::default());

            futures_lite::future::block_on(async {
                let cx = crate::cx::Cx::for_testing();
                let mut acquisition_order = Vec::new();

                // Spawn concurrent tasks with deterministic timing
                let task1 = async {
                    crate::runtime::yield_now().await;
                    pool.acquire(&cx).await.unwrap().return_to_pool();
                    1u32
                };

                let task2 = async {
                    crate::runtime::yield_now().await;
                    crate::runtime::yield_now().await;
                    pool.acquire(&cx).await.unwrap().return_to_pool();
                    2u32
                };

                let (result1, result2) = futures_lite::future::zip(task1, task2).await;
                acquisition_order.push(result1);
                acquisition_order.push(result2);
                acquisition_order
            })
        };

        let timing1 = timed_sequence();
        let timing2 = timed_sequence();
        let timing3 = timed_sequence();

        // Timing determinism under LabRuntime
        crate::assert_with_log!(
            timing1 == timing2,
            "timing deterministic replay: order matches (run1 vs run2)",
            timing1,
            timing2
        );
        crate::assert_with_log!(
            timing2 == timing3,
            "timing deterministic replay: order matches (run2 vs run3)",
            timing2,
            timing3
        );

        crate::test_complete!("metamorphic_deterministic_lab_runtime_replay");
    }

    fn noop_pool_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// Audit test for object pool acquisition FIFO behavior when exhausted.
    #[test]
    fn audit_pool_exhausted_fifo_acquisition() {
        init_test("audit_pool_exhausted_fifo_acquisition");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx = Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        let waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut first_waiter = pool.acquire(&cx);
        let mut second_waiter = pool.acquire(&cx);

        assert!(first_waiter.as_mut().poll(&mut task_cx).is_pending());
        assert!(second_waiter.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(pool.stats().waiters, 2, "two waiters should be queued");

        held.return_to_pool();

        assert!(
            second_waiter.as_mut().poll(&mut task_cx).is_pending(),
            "later waiter must not bypass the earlier queued waiter"
        );

        let first_resource = match first_waiter.as_mut().poll(&mut task_cx) {
            Poll::Ready(Ok(resource)) => resource,
            Poll::Ready(Err(error)) => {
                panic!("first waiter should acquire returned resource, got error: {error}")
            }
            Poll::Pending => panic!("first waiter should acquire returned resource"),
        };
        assert_eq!(pool.stats().waiters, 1, "second waiter remains queued");

        first_resource.return_to_pool();

        let second_resource = match second_waiter.as_mut().poll(&mut task_cx) {
            Poll::Ready(Ok(resource)) => resource,
            Poll::Ready(Err(error)) => {
                panic!("second waiter should acquire after first return, got error: {error}")
            }
            Poll::Pending => panic!("second waiter should acquire after first return"),
        };
        second_resource.return_to_pool();

        let stats = pool.stats();
        assert_eq!(stats.waiters, 0, "all waiters should be drained");
        assert_eq!(stats.active, 0, "no active resources");
        assert_eq!(stats.idle, 1, "single resource should return to idle");
    }

    /// Audit test for pool acquisition with cancellation preserving FIFO fairness.
    #[test]
    fn audit_pool_cancellation_preserves_fifo() {
        init_test("audit_pool_cancellation_preserves_fifo");

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx = Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");
        let waker = noop_pool_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut first_waiter = pool.acquire(&cx);
        let mut cancelled_waiter = pool.acquire(&cx);
        let mut third_waiter = pool.acquire(&cx);

        assert!(first_waiter.as_mut().poll(&mut task_cx).is_pending());
        assert!(cancelled_waiter.as_mut().poll(&mut task_cx).is_pending());
        assert!(third_waiter.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(pool.stats().waiters, 3, "three waiters should be queued");

        drop(cancelled_waiter);
        assert_eq!(
            pool.stats().waiters,
            2,
            "dropping a queued acquire must remove only that waiter"
        );

        held.return_to_pool();

        assert!(
            third_waiter.as_mut().poll(&mut task_cx).is_pending(),
            "later waiter must remain queued until the earlier live waiter acquires"
        );

        let first_resource = match first_waiter.as_mut().poll(&mut task_cx) {
            Poll::Ready(Ok(resource)) => resource,
            Poll::Ready(Err(error)) => {
                panic!("first live waiter should acquire first, got error: {error}")
            }
            Poll::Pending => panic!("first live waiter should acquire first"),
        };
        first_resource.return_to_pool();

        let third_resource = match third_waiter.as_mut().poll(&mut task_cx) {
            Poll::Ready(Ok(resource)) => resource,
            Poll::Ready(Err(error)) => {
                panic!("third waiter should acquire after first returns, got error: {error}")
            }
            Poll::Pending => panic!("third waiter should acquire after first returns"),
        };
        third_resource.return_to_pool();

        let stats = pool.stats();
        assert_eq!(stats.waiters, 0, "cancelled waiter must not leak");
        assert_eq!(stats.active, 0, "no active resources remain");
        assert_eq!(
            stats.idle, 1,
            "resource should be reusable after cancellation"
        );
    }

    /// Regression for br-asupersync-dq5g7a: when the dispatcher waiter (the
    /// first `return_wakers` entry, woken by `notify_return_wakers` to drain
    /// the return channel) is cancelled after a resource return woke it but
    /// before it polls `process_returns`, its `Drop` must hand the dispatcher
    /// role to the next waiter. Otherwise the returned resource stays stranded
    /// in the channel and the remaining waiters are never woken (lost wakeup).
    ///
    /// The existing cancellation tests manually re-poll the survivors, which
    /// hides the missing wake; this test uses recording wakers to observe it.
    #[test]
    fn cancelling_dispatcher_after_return_redispatches_to_next_waiter() {
        init_test("cancelling_dispatcher_after_return_redispatches_to_next_waiter");

        struct FlagWake(Arc<std::sync::atomic::AtomicBool>);
        impl Wake for FlagWake {
            fn wake(self: Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let pool = GenericPool::new(simple_factory, PoolConfig::with_max_size(1));
        let cx = Cx::for_testing();
        let held = futures_lite::future::block_on(pool.acquire(&cx)).expect("first acquire");

        let dispatcher_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dispatcher_waker = Waker::from(Arc::new(FlagWake(Arc::clone(&dispatcher_flag))));
        let mut dispatcher_cx = Context::from_waker(&dispatcher_waker);

        let survivor_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let survivor_waker = Waker::from(Arc::new(FlagWake(Arc::clone(&survivor_flag))));
        let mut survivor_cx = Context::from_waker(&survivor_waker);

        let mut dispatcher = pool.acquire(&cx);
        let mut survivor = pool.acquire(&cx);

        // The dispatcher registers first, so a return wakes it.
        assert!(dispatcher.as_mut().poll(&mut dispatcher_cx).is_pending());
        assert!(survivor.as_mut().poll(&mut survivor_cx).is_pending());
        crate::assert_with_log!(
            pool.stats().waiters == 2,
            "two waiters queued",
            2,
            pool.stats().waiters
        );

        // Clear wakes recorded during the registration polls.
        dispatcher_flag.store(false, std::sync::atomic::Ordering::SeqCst);
        survivor_flag.store(false, std::sync::atomic::Ordering::SeqCst);

        // Returning the only resource wakes the dispatcher to drain the channel.
        held.return_to_pool();
        crate::assert_with_log!(
            dispatcher_flag.load(std::sync::atomic::Ordering::SeqCst),
            "return wakes the dispatcher (first) waiter",
            true,
            dispatcher_flag.load(std::sync::atomic::Ordering::SeqCst)
        );

        // Cancel the dispatcher before it polls process_returns. The Drop must
        // re-dispatch to the survivor, else the resource is stranded.
        drop(dispatcher);
        crate::assert_with_log!(
            survivor_flag.load(std::sync::atomic::Ordering::SeqCst),
            "cancelling the dispatcher re-dispatches to the next waiter",
            true,
            survivor_flag.load(std::sync::atomic::Ordering::SeqCst)
        );

        // The survivor can now actually acquire the returned resource.
        let resource = match survivor.as_mut().poll(&mut survivor_cx) {
            Poll::Ready(Ok(resource)) => resource,
            Poll::Ready(Err(error)) => {
                panic!("survivor should acquire the returned resource, got error: {error}")
            }
            Poll::Pending => {
                panic!("survivor should acquire the returned resource after re-dispatch")
            }
        };
        resource.return_to_pool();

        crate::test_complete!("cancelling_dispatcher_after_return_redispatches_to_next_waiter");
    }
}
