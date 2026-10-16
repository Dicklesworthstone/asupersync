    use super::*;
    use crate::channel::{broadcast, mpsc, oneshot, session, watch};
    use crate::cx::Cx;
    use crate::sync::{Barrier, Mutex, OnceCell, RwLock, Semaphore};
    use crate::types::{Budget, CancelKind};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    fn poll<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(std::task::Waker::noop()))
    }

    fn returned(cx: &Cx, id: &str) -> FiniteResponsiveness {
        ResponsivenessRegistry::lookup(id)
            .expect("maintained entry")
            .bound(
                ResponsivenessGoal::OperationReturned,
                ResponsivenessQuery::for_cx(cx, CancelKind::User),
            )
            .expect("conditional operation-return bound")
    }

    // These are delivered-poll unit witnesses, deliberately not native scheduler
    // or wake-delivery proofs. Every caller first checks its real parked state.
    fn cancel_parked<F: Future + ?Sized>(cx: &Cx, id: &str, mut future: Pin<&mut F>) -> F::Output {
        assert!(poll(future.as_mut()).is_pending(), "{id}: still withheld");
        let bound = returned(cx, id);
        let before = cx.checkpoint_state().checkpoint_count;
        cx.cancel_with(CancelKind::User, Some("stock responsiveness witness"));
        let result = poll(future);
        bound
            .check_observed(1, result.is_ready())
            .expect("actual return");
        let delta = cx.checkpoint_state().checkpoint_count - before;
        assert!(delta > 0, "{id}: actual checkpoint after publication");
        assert!(
            cx.inner.read().cancel_acknowledged,
            "{id}: actual acknowledgement"
        );
        println!(
            "ASUPERSYNC_RESPONSIVENESS_UNIT {}",
            serde_json::json!({
                "entry": id, "unit": "operation_polls", "post_cancel_polls": 1,
                "checkpoint_delta": delta, "acknowledged": true,
                "scope": "manually_delivered_stock_operation_poll"
            })
        );
        match result {
            Poll::Ready(value) => value,
            Poll::Pending => unreachable!("the measured Ready predicate was required"),
        }
    }

    #[test]
    fn responsiveness_mpsc_and_tracked_capacity_cancel_before_commit() {
        for variant in 0..4 {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::channel::<u8>(1);
            sender.try_send(7).expect("actual occupied physical slot");
            let tracked = session::TrackedSender::new(sender.clone());
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = match variant {
                0 => Box::pin(async {
                    assert!(matches!(
                        sender.reserve(&cx).await,
                        Err(mpsc::SendError::Cancelled(()))
                    ));
                }),
                1 => Box::pin(async {
                    assert!(matches!(
                        sender.reserve_checked(&cx).await,
                        Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(
                            ()
                        )))
                    ));
                }),
                2 => Box::pin(async {
                    assert!(matches!(
                        tracked.reserve(&cx).await,
                        Err(mpsc::SendError::Cancelled(()))
                    ));
                }),
                _ => Box::pin(async {
                    assert!(matches!(
                        tracked.reserve_checked(&cx).await,
                        Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(
                            ()
                        )))
                    ));
                }),
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1);
            cancel_parked(
                &cx,
                if variant < 2 {
                    "mpsc.reserve"
                } else {
                    "session.reserve"
                },
                wait.as_mut(),
            );
            drop(wait);
            let snapshot = sender.telemetry_snapshot(1);
            assert_eq!(snapshot.send_waiter_count, 0);
            assert_eq!(snapshot.reserved_uncommitted_obligations, 0);
            assert_eq!(snapshot.queued_messages, 1);
            assert_eq!(receiver.try_recv(), Ok(7));
            assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
        }
    }

    #[test]
    fn responsiveness_channel_receivers_cancel_from_actual_empty_waits() {
        for many in [false, true] {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::channel::<u8>(1);
            let mut values = Vec::new();
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = if many {
                Box::pin(async {
                    assert_eq!(
                        receiver.recv_many(&cx, &mut values, 1).await,
                        Err(mpsc::RecvError::Cancelled)
                    );
                })
            } else {
                Box::pin(async {
                    assert_eq!(receiver.recv(&cx).await, Err(mpsc::RecvError::Cancelled));
                })
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(2).recv_waiter_count, 1);
            cancel_parked(&cx, "mpsc.receive", wait.as_mut());
            drop(wait);
            assert!(values.is_empty());
            assert_eq!(sender.telemetry_snapshot(2).recv_waiter_count, 0);
            sender
                .try_send(11)
                .expect("cancellation did not close receiver");
            assert_eq!(receiver.try_recv(), Ok(11));
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::unbounded::<u8>();
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(3).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "mpsc.receive", wait.as_mut()),
                Err(mpsc::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(3).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = oneshot::channel::<u8>();
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(4).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "oneshot.receive", wait.as_mut()),
                Err(oneshot::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(4).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = broadcast::channel::<u8>(1);
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(5).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "broadcast.receive", wait.as_mut()),
                Err(broadcast::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(5).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = watch::channel(9_u8);
            let mut wait = Box::pin(receiver.changed(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(sender.telemetry_snapshot(6).recv_waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "watch.changed", wait.as_mut()),
                Err(watch::RecvError::Cancelled)
            );
            drop(wait);
            assert_eq!(sender.telemetry_snapshot(6).recv_waiter_count, 0);
            assert_eq!(*receiver.borrow(), 9);
        }
    }

    #[test]
    fn responsiveness_locks_and_semaphore_do_not_need_holder_release() {
        for owned in [false, true] {
            let cx = Cx::for_testing();
            let mutex = Arc::new(Mutex::new(17_u8));
            let held = mutex.try_lock().expect("actual held mutex");
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = if owned {
                Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedMutexGuard::lock(Arc::clone(&mutex), &cx).await,
                        Err(crate::sync::LockError::Cancelled)
                    ));
                })
            } else {
                Box::pin(async {
                    assert!(matches!(
                        mutex.lock(&cx).await,
                        Err(crate::sync::LockError::Cancelled)
                    ));
                })
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(mutex.waiters(), 1);
            cancel_parked(&cx, "mutex.lock", wait.as_mut());
            drop(wait);
            assert_eq!(mutex.waiters(), 0);
            assert_eq!(*held, 17);
            assert!(mutex.try_lock().is_err());
            drop(held);
            assert_eq!(*mutex.try_lock().expect("physical recovery"), 17);
        }
        for variant in 0..4 {
            let cx = Cx::for_testing();
            let lock = Arc::new(RwLock::new(19_u8));
            let held = lock
                .try_write()
                .expect("actual writer excludes all variants");
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = match variant {
                0 => Box::pin(async {
                    assert!(matches!(
                        lock.read(&cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
                1 => Box::pin(async {
                    assert!(matches!(
                        lock.write(&cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
                2 => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedRwLockReadGuard::read(Arc::clone(&lock), &cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
                _ => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedRwLockWriteGuard::write(Arc::clone(&lock), &cx).await,
                        Err(crate::sync::RwLockError::Cancelled)
                    ));
                }),
            };
            assert!(poll(wait.as_mut()).is_pending());
            cancel_parked(&cx, "rwlock.acquire", wait.as_mut());
            drop(wait);
            assert!(lock.try_read().is_err());
            assert_eq!(*held, 19);
            drop(held);
            assert_eq!(
                *lock
                    .try_write()
                    .expect("cancelled queue no longer blocks writer"),
                19
            );
        }
        for variant in 0..4 {
            let cx = Cx::for_testing();
            let semaphore = Arc::new(Semaphore::new(1));
            let held = semaphore.try_acquire(1).expect("physical permit held");
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = match variant {
                0 => Box::pin(async {
                    assert!(matches!(
                        semaphore.acquire(&cx, 1).await,
                        Err(crate::sync::AcquireError::Cancelled)
                    ));
                }),
                1 => Box::pin(async {
                    assert!(matches!(
                        semaphore.acquire_checked(&cx, 1).await,
                        Err(crate::sync::semaphore::CheckedAcquireError::Semaphore(
                            crate::sync::AcquireError::Cancelled
                        ))
                    ));
                }),
                2 => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedSemaphorePermit::acquire(Arc::clone(&semaphore), &cx, 1)
                            .await,
                        Err(crate::sync::AcquireError::Cancelled)
                    ));
                }),
                _ => Box::pin(async {
                    assert!(matches!(
                        crate::sync::OwnedSemaphorePermit::acquire_checked(
                            Arc::clone(&semaphore),
                            &cx,
                            1
                        )
                        .await,
                        Err(crate::sync::semaphore::CheckedAcquireError::Semaphore(
                            crate::sync::AcquireError::Cancelled
                        ))
                    ));
                }),
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(semaphore.telemetry_snapshot(8).waiter_count, 1);
            cancel_parked(&cx, "semaphore.acquire", wait.as_mut());
            drop(wait);
            assert_eq!(semaphore.telemetry_snapshot(8).waiter_count, 0);
            assert_eq!(semaphore.available_permits(), 0);
            drop(held);
            assert_eq!(semaphore.available_permits(), 1);
        }
    }

    fn timer_context() -> (
        Cx,
        Arc<crate::time::VirtualClock>,
        crate::time::TimerDriverHandle,
    ) {
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        (cx, clock, timer)
    }

    #[test]
    fn responsiveness_pool_cell_and_barrier_cancel_without_external_progress() {
        use crate::sync::{GenericPool, Pool, PoolConfig, PoolError};
        for checked in [false, true] {
            let (cx, _clock, timer) = timer_context();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let pool = GenericPool::new(
                || std::future::ready(Ok::<_, std::io::Error>(23_u8)),
                PoolConfig::with_max_size(1),
            );
            let mut first = pool.acquire(&cx);
            let held = match poll(first.as_mut()) {
                Poll::Ready(Ok(held)) => held,
                Poll::Ready(Err(error)) => panic!("ready factory acquisition failed: {error}"),
                Poll::Pending => panic!("ready factory unexpectedly suspended"),
            };
            drop(first);
            let mut wait: Pin<Box<dyn Future<Output = ()> + '_>> = if checked {
                Box::pin(async {
                    assert!(matches!(
                        pool.acquire_checked(&cx).await,
                        Err(crate::sync::CheckedPoolError::Pool(PoolError::Cancelled))
                    ));
                })
            } else {
                Box::pin(async {
                    assert!(matches!(pool.acquire(&cx).await, Err(PoolError::Cancelled)));
                })
            };
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(pool.stats().waiters, 1);
            assert_eq!(pool.stats().active, 1);
            cancel_parked(&cx, "pool.capacity-wait", wait.as_mut());
            drop(wait);
            assert_eq!(pool.stats().waiters, 0);
            assert_eq!(
                pool.stats().active,
                1,
                "holder did not release to satisfy waiter"
            );
            drop(held);
            assert_eq!(pool.stats().active, 0);
            assert_eq!(pool.stats().idle, 1);
            assert!(poll(pool.close().as_mut()).is_ready());
            assert_eq!(pool.stats().total, 0);
            assert_eq!(timer.pending_count(), 0);
        }
        {
            let cx = Cx::for_testing();
            let cell = OnceCell::<u8>::new();
            let mut wait = Box::pin(cell.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(cell.telemetry_snapshot(9).waiter_count, 1);
            assert_eq!(
                cancel_parked(&cx, "once-cell.wait", wait.as_mut()),
                Err(crate::sync::OnceCellError::Cancelled)
            );
            drop(wait);
            assert_eq!(cell.telemetry_snapshot(9).waiter_count, 0);
            assert!(!cell.is_initialized());
            cell.set(31)
                .expect("cancellation did not initialize or poison cell");
            assert_eq!(cell.get(), Some(&31));
        }
        {
            let cx = Cx::for_testing();
            let barrier = Barrier::new(2);
            let mut wait = Box::pin(barrier.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(barrier.telemetry_snapshot(10).waiter_count, 1);
            assert_eq!(barrier.telemetry_snapshot(10).occupied_units, 1);
            assert!(matches!(
                cancel_parked(&cx, "barrier.wait", wait.as_mut()),
                Err(crate::sync::BarrierWaitError::Cancelled)
            ));
            drop(wait);
            assert_eq!(barrier.telemetry_snapshot(10).waiter_count, 0);
            assert_eq!(barrier.telemetry_snapshot(10).occupied_units, 0);
            assert_eq!(barrier.telemetry_snapshot(10).generation, 0);
        }
    }

    #[test]
    fn responsiveness_ready_values_zero_units_and_barrier_precedence_are_explicit() {
        for closed in [false, true] {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = oneshot::channel::<u8>();
            let mut wait = Box::pin(receiver.recv(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(CancelKind::User, Some("value and cancellation race"));
            if closed {
                drop(sender);
            } else {
                sender
                    .send(&Cx::for_testing(), 41)
                    .expect("independent producer commits real value");
            }
            let result = poll(wait.as_mut());
            assert_eq!(
                result,
                Poll::Ready(if closed {
                    Err(oneshot::RecvError::Closed)
                } else {
                    Ok(41)
                })
            );
            assert_eq!(
                cx.checkpoint_state().checkpoint_count,
                before,
                "ready result precedes checkpoint"
            );
            assert!(!cx.inner.read().cancel_acknowledged);
            returned(&cx, "oneshot.receive")
                .check_observed(1, result.is_ready())
                .unwrap();
            assert_eq!(
                ResponsivenessRegistry::lookup("oneshot.receive")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::CancellationObserved,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::CompletionMayWin)
            );
            drop(wait);
            assert_eq!(receiver.telemetry_snapshot(11).recv_waiter_count, 0);
        }
        {
            let cx = Cx::for_testing();
            let cell = OnceCell::new();
            let mut wait = Box::pin(cell.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(CancelKind::User, Some("initialized value wins"));
            cell.set(43_u8).unwrap();
            assert_eq!(poll(wait.as_mut()), Poll::Ready(Ok(())));
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert!(!cx.inner.read().cancel_acknowledged);
            drop(wait);
            assert_eq!(cell.telemetry_snapshot(12).waiter_count, 0);
            assert_eq!(
                ResponsivenessRegistry::lookup("once-cell.wait")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::CancellationObserved,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::CompletionMayWin)
            );
        }
        for checked in [false, true] {
            let cx = Cx::for_testing();
            let semaphore = Semaphore::new(0);
            cx.cancel_with(CancelKind::User, Some("zero units do not checkpoint"));
            let before = cx.checkpoint_state().checkpoint_count;
            if checked {
                let mut wait = Box::pin(semaphore.acquire_checked(&cx, 0));
                assert!(matches!(poll(wait.as_mut()), Poll::Ready(Ok(_))));
            } else {
                let mut wait = Box::pin(semaphore.acquire(&cx, 0));
                assert!(matches!(poll(wait.as_mut()), Poll::Ready(Ok(_))));
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert!(!cx.inner.read().cancel_acknowledged);
            assert_eq!(semaphore.telemetry_snapshot(13).waiter_count, 0);
            assert_eq!(returned(&cx, "semaphore.zero").steps(), 1);
            assert_eq!(
                ResponsivenessRegistry::lookup("semaphore.zero")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::CancellationObserved,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::CompletionMayWin)
            );
        }
        {
            let cx = Cx::for_testing();
            let peer = Cx::for_testing();
            let barrier = Barrier::new(2);
            let mut wait = Box::pin(barrier.wait(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            let mut second = Box::pin(barrier.wait(&peer));
            assert!(matches!(poll(second.as_mut()), Poll::Ready(Ok(_))));
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(CancelKind::User, Some("generation already committed"));
            assert!(matches!(poll(wait.as_mut()), Poll::Ready(Ok(_))));
            assert!(cx.checkpoint_state().checkpoint_count > before);
            assert!(cx.inner.read().cancel_acknowledged);
            drop(wait);
            drop(second);
            assert_eq!(barrier.telemetry_snapshot(14).generation, 1);
            assert_eq!(barrier.telemetry_snapshot(14).waiter_count, 0);
            assert_eq!(barrier.telemetry_snapshot(14).occupied_units, 0);
        }
    }

    #[test]
    fn responsiveness_sleep_requires_ambient_context_and_distinguishes_timer_cancellation() {
        use crate::time::Sleep;
        use crate::types::Time;
        {
            let (cx, _clock, timer) = timer_context();
            assert_eq!(
                ResponsivenessRegistry::lookup("sleep.cancel")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::MissingAmbientContext)
            );
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut wait = Box::pin(Sleep::new(Time::from_secs(1)));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(timer.pending_count(), 1);
            cancel_parked(&cx, "sleep.cancel", wait.as_mut());
            drop(wait);
            assert_eq!(timer.pending_count(), 0);
        }
        for kind in [CancelKind::Timeout, CancelKind::Deadline] {
            let (cx, clock, timer) = timer_context();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut wait = Box::pin(Sleep::new(Time::from_secs(1)));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(timer.pending_count(), 1);
            let before = cx.checkpoint_state().checkpoint_count;
            cx.cancel_with(kind, Some("timer completion remains required"));
            assert_eq!(
                ResponsivenessRegistry::lookup("sleep.cancel")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, kind)
                    ),
                Err(ResponsivenessRefusal::TimerProgress)
            );
            for _ in 0..3 {
                assert!(poll(wait.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert_eq!(timer.pending_count(), 1);
            clock.set(Time::from_secs(1));
            assert_eq!(timer.process_timers(), 1, "actual registered timer fires");
            assert_eq!(poll(wait.as_mut()), Poll::Ready(()));
            drop(wait);
            assert_eq!(timer.pending_count(), 0);
        }
    }

    #[derive(Default)]
    struct WriteState {
        released: bool,
        calls: usize,
        bytes: Vec<u8>,
        waiter: Option<std::task::Waker>,
    }

    struct ControlledIo {
        input: &'static [u8],
        writes: Arc<parking_lot::Mutex<WriteState>>,
    }

    impl ControlledIo {
        fn new() -> (Self, Arc<parking_lot::Mutex<WriteState>>) {
            let writes = Arc::new(parking_lot::Mutex::new(WriteState::default()));
            (
                Self {
                    input: b"0123456789abcdef",
                    writes: Arc::clone(&writes),
                },
                writes,
            )
        }
    }

    impl crate::io::AsyncRead for ControlledIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            crate::io::AsyncRead::poll_read(Pin::new(&mut self.input), cx, buf)
        }
    }

    impl crate::io::AsyncWrite for ControlledIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut state = self.writes.lock();
            state.calls += 1;
            if !state.released {
                state.waiter = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let count = buf.len().min(1);
            state.bytes.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn release_writes(state: &parking_lot::Mutex<WriteState>) {
        let waiter = {
            let mut state = state.lock();
            state.released = true;
            state.waiter.take()
        };
        waiter
            .expect("actual withheld write poll registered a waiter")
            .wake();
    }

    fn cancel_copy<T, F: Future<Output = std::io::Result<T>> + ?Sized>(
        cx: &Cx,
        id: &str,
        mut copy: Pin<&mut F>,
        writers: &[Arc<parking_lot::Mutex<WriteState>>],
        expected_attempts: usize,
    ) {
        assert!(poll(copy.as_mut()).is_pending());
        assert!(
            poll(copy.as_mut()).is_pending(),
            "actual retained prefix stays blocked"
        );
        let previous: Vec<_> = writers
            .iter()
            .map(|writer| {
                let writer = writer.lock();
                assert!(writer.waiter.is_some());
                assert!(writer.bytes.is_empty());
                writer.calls
            })
            .collect();
        let bound = returned(cx, id);
        let before = cx.checkpoint_state().checkpoint_count;
        cx.cancel_with(CancelKind::User, Some("copy cancellation drain"));
        for writer in writers {
            release_writes(writer);
        }
        let result = poll(copy);
        bound.check_observed(1, result.is_ready()).unwrap();
        assert!(
            matches!(result, Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted)
        );
        assert!(cx.checkpoint_state().checkpoint_count > before);
        let attempts: usize = writers
            .iter()
            .zip(previous)
            .map(|(writer, previous)| writer.lock().calls - previous)
            .sum();
        assert_eq!(
            attempts, expected_attempts,
            "causal nested write-poll boundary"
        );
        assert_eq!(u64::try_from(attempts).unwrap(), bound.io_write_attempts());
        for writer in writers {
            let writer = writer.lock();
            assert_eq!(
                writer.bytes.as_slice(),
                if expected_attempts == 0 {
                    b"".as_slice()
                } else {
                    b"0123".as_slice()
                }
            );
            assert!(writer.waiter.is_none());
        }
        println!(
            "ASUPERSYNC_RESPONSIVENESS_IO {}",
            serde_json::json!({
                "entry": id, "post_cancel_polls": 1, "actual_write_attempts": attempts,
                "result": "Interrupted", "scope": "stock_copy_with_controlled_pending_provider",
                "full_delivery": false
            })
        );
    }

    #[test]
    fn responsiveness_copy_variants_enforce_real_bounded_cancel_drain() {
        for progress in [false, true] {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut reader = &b"0123456789abcdef"[..];
            let (mut writer, state) = ControlledIo::new();
            let mut observed = Vec::new();
            let mut copy: Pin<Box<dyn Future<Output = std::io::Result<u64>> + '_>> = if progress {
                Box::pin(crate::io::copy_with_progress(
                    &mut reader,
                    &mut writer,
                    |bytes| observed.push(bytes),
                ))
            } else {
                Box::pin(crate::io::copy(&mut reader, &mut writer))
            };
            cancel_copy(&cx, "io.copy", copy.as_mut(), &[state], 4);
            drop(copy);
            assert!(
                reader.is_empty(),
                "private read-ahead consumed the real input"
            );
            assert_eq!(observed, if progress { vec![4] } else { vec![] });
        }
        {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let mut reader = crate::io::BufReader::new(&b"0123456789abcdef"[..]);
            let (mut writer, state) = ControlledIo::new();
            let mut copy = Box::pin(crate::io::copy_buf(&mut reader, &mut writer));
            cancel_copy(&cx, "io.copy-buf", copy.as_mut(), &[state], 0);
            drop(copy);
            // End the cancelled ambient scope before resuming. Installing None
            // is a no-op on the context stack; it does not hide an outer Cx.
            drop(_ambient);
            assert!(Cx::current().is_none());
            let mut retained = Vec::new();
            let mut continuation = Box::pin(crate::io::copy_buf(&mut reader, &mut retained));
            let resumed = poll(continuation.as_mut());
            assert!(
                matches!(&resumed, Poll::Ready(Ok(16))),
                "the full buffered prefix survives cancellation: {resumed:?}"
            );
            drop(continuation);
            assert_eq!(retained, b"0123456789abcdef");
        }
        {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let (mut a, a_state) = ControlledIo::new();
            let (mut b, b_state) = ControlledIo::new();
            let mut copy = Box::pin(crate::io::copy_bidirectional(&mut a, &mut b));
            cancel_copy(
                &cx,
                "io.copy-bidirectional",
                copy.as_mut(),
                &[a_state, b_state],
                8,
            );
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn responsiveness_native_socket_waits_check_before_io_on_delivered_poll() {
        use crate::runtime::io_driver::IoDriverHandle;
        for variant in 0..3 {
            let driver = IoDriverHandle::new(
                crate::runtime::reactor::create_reactor().expect("actual OS reactor"),
            );
            let cx = Cx::new_with_drivers(
                crate::types::RegionId::new_for_test(0, 1),
                crate::types::TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
                None,
                None,
            );
            let _ambient = Cx::set_current(Some(cx.clone()));
            if variant > 0 {
                let raw = std::net::UdpSocket::bind("127.0.0.1:0").expect("owned real UDP socket");
                let mut socket = crate::net::UdpSocket::from_std(raw).unwrap();
                let mut bytes = [0_u8; 16];
                let mut wait = Box::pin(std::future::poll_fn(|context| {
                    if variant == 1 {
                        socket.poll_recv_from(context, &mut bytes)
                    } else {
                        socket.poll_peek_from(context, &mut bytes)
                    }
                }));
                assert!(poll(wait.as_mut()).is_pending());
                assert_eq!(driver.waker_count(), 1);
                assert!(matches!(cancel_parked(&cx, "net.udp-wait", wait.as_mut()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted));
                drop(wait);
                drop(socket);
                assert_eq!(bytes, [0_u8; 16]);
            } else {
                let raw =
                    std::net::TcpListener::bind("127.0.0.1:0").expect("owned real TCP listener");
                let listener = crate::net::TcpListener::from_std(raw).unwrap();
                let mut wait = Box::pin(std::future::poll_fn(|context| {
                    listener.poll_accept(context)
                }));
                assert!(poll(wait.as_mut()).is_pending());
                assert_eq!(driver.waker_count(), 1);
                assert!(matches!(cancel_parked(&cx, "net.tcp-wait", wait.as_mut()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted));
                drop(wait);
                drop(listener);
            }
            assert_eq!(
                driver.waker_count(),
                0,
                "actual socket owner Drop retires reactor registration"
            );
        }
    }

    fn nested_masks(cx: &Cx, remaining: u32, body: &mut dyn FnMut()) {
        if remaining == 0 {
            body();
        } else {
            cx.masked(|| nested_masks(cx, remaining - 1, body));
        }
    }

    #[test]
    fn responsiveness_actual_masks_and_budget_edges_refuse_unsound_composition() {
        let cx = Cx::for_testing();
        let one = returned(&cx, "mutex.lock");
        assert_eq!(one.unit(), ResponsivenessUnit::OperationPolls);
        let three = one.checked_repeat(3).unwrap();
        for quota in [2, 3, 4] {
            let actual = three.check_poll_budget(Budget::INFINITE.with_poll_quota(quota));
            if quota == 2 {
                assert_eq!(
                    actual,
                    Err(ResponsivenessRefusal::InsufficientPollBudget {
                        required: 3,
                        available: 2
                    })
                );
            } else {
                assert_eq!(actual, Ok(three));
            }
        }
        assert_eq!(
            one.check_poll_budget(Budget::INFINITE.with_poll_quota(0)),
            Err(ResponsivenessRefusal::InsufficientPollBudget {
                required: 1,
                available: 0
            })
        );
        assert!(
            one.check_poll_budget(Budget::INFINITE.with_poll_quota(1))
                .is_ok()
        );
        assert!(
            one.check_poll_budget(Budget::INFINITE.with_poll_quota(2))
                .is_ok()
        );
        let empty = one.checked_repeat(0).unwrap();
        assert_eq!(empty.steps(), 0);
        assert!(
            empty
                .check_poll_budget(Budget::INFINITE.with_poll_quota(0))
                .is_ok()
        );
        let largest = one.checked_repeat(u64::MAX).unwrap();
        assert_eq!(
            largest.checked_repeat(2),
            Err(ResponsivenessRefusal::Overflow)
        );
        assert_eq!(
            largest.checked_then(one),
            Err(ResponsivenessRefusal::Overflow)
        );
        assert!(
            largest.check_poll_budget(Budget::INFINITE).is_ok(),
            "unlimited sentinel, not elapsed-time evidence"
        );
        {
            let _ambient = Cx::set_current(Some(cx.clone()));
            assert_eq!(
                returned(&cx, "io.copy").checked_repeat(u64::MAX),
                Err(ResponsivenessRefusal::Overflow),
                "independent inner-write accounting cannot overflow"
            );
        }
        let checkpoint = ResponsivenessRegistry::lookup("Cx::checkpoint")
            .unwrap()
            .bound(
                ResponsivenessGoal::OperationReturned,
                ResponsivenessQuery::for_cx(&cx, CancelKind::User),
            )
            .unwrap();
        assert_eq!(checkpoint.unit(), ResponsivenessUnit::CheckpointCalls);
        assert_eq!(
            one.checked_then(checkpoint),
            Err(ResponsivenessRefusal::DifferentUnits)
        );
        assert_eq!(
            checkpoint.check_poll_budget(Budget::INFINITE),
            Err(ResponsivenessRefusal::DifferentUnits)
        );
        let observed = ResponsivenessRegistry::lookup("mutex.lock")
            .unwrap()
            .bound(
                ResponsivenessGoal::CancellationObserved,
                ResponsivenessQuery::for_cx(&cx, CancelKind::User),
            )
            .unwrap();
        assert_eq!(
            one.checked_then(observed),
            Err(ResponsivenessRefusal::DifferentGoals)
        );
        assert_eq!(
            one.check_observed(2, true),
            Err(ResponsivenessRefusal::PollBoundExceeded {
                bound: 1,
                observed: 2
            })
        );
        assert_eq!(
            ResponsivenessRegistry::checked_mask_depth(u32::MAX, 1),
            Err(ResponsivenessRefusal::Overflow)
        );
        assert_eq!(
            ResponsivenessRegistry::checked_mask_depth(64, 1),
            Err(ResponsivenessRefusal::MaskDepthExceeded {
                depth: 65,
                maximum: 64
            })
        );
        for depth in [1, crate::types::task_context::MAX_MASK_DEPTH] {
            let cx = Cx::for_testing();
            let mutex = Mutex::new(());
            let held = mutex.try_lock().unwrap();
            let mut wait = Box::pin(mutex.lock(&cx));
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(mutex.waiters(), 1);
            cx.cancel_with(CancelKind::User, Some("actual nested masks"));
            nested_masks(&cx, depth, &mut || {
                let query = ResponsivenessQuery::for_cx(&cx, CancelKind::User);
                assert_eq!(
                    ResponsivenessRegistry::lookup("mutex.lock")
                        .unwrap()
                        .bound(ResponsivenessGoal::OperationReturned, query),
                    Err(ResponsivenessRefusal::Masked { depth })
                );
                assert!(
                    poll(wait.as_mut()).is_pending(),
                    "real mask withholds cancellation while holder remains"
                );
                assert!(!cx.inner.read().cancel_acknowledged);
                assert_eq!(mutex.waiters(), 1);
                if depth == 64 {
                    assert_eq!(
                        query.with_additional_masks(1).unwrap_err(),
                        ResponsivenessRefusal::MaskDepthExceeded {
                            depth: 65,
                            maximum: 64
                        }
                    );
                }
            });
            assert_eq!(cx.inner.read().mask_depth, 0, "all actual guards unwound");
            let outcome = poll(wait.as_mut());
            assert!(matches!(
                outcome,
                Poll::Ready(Err(crate::sync::LockError::Cancelled))
            ));
            one.check_observed(1, outcome.is_ready()).unwrap();
            assert!(cx.inner.read().cancel_acknowledged);
            drop(wait);
            assert_eq!(mutex.waiters(), 0);
            assert!(mutex.try_lock().is_err());
            drop(held);
            assert!(mutex.try_lock().is_ok());
        }
        let before = cx.checkpoint_state().checkpoint_count;
        cx.cancel_with(
            CancelKind::User,
            Some("explicit synchronous checkpoint call"),
        );
        let result = cx.checkpoint();
        checkpoint.check_observed(1, result.is_err()).unwrap();
        assert_eq!(cx.checkpoint_state().checkpoint_count, before + 1);
        assert!(cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn responsiveness_withheld_notification_and_factory_fail_the_same_boundary_checker() {
        use crate::sync::{GenericPool, Notify, Pool, PoolConfig};
        {
            let cx = Cx::for_testing();
            let notify = Notify::new();
            let mut wait = Box::pin(notify.notified());
            assert!(poll(wait.as_mut()).is_pending());
            assert_eq!(notify.waiter_count(), 1);
            let wrongly_applied_finite_bound = returned(&cx, "mutex.lock");
            cx.cancel_with(
                CancelKind::User,
                Some("notification deliberately withholds progress"),
            );
            let before = cx.checkpoint_state().checkpoint_count;
            for polls in 1..=3 {
                let result = poll(wait.as_mut());
                assert_eq!(
                    wrongly_applied_finite_bound.check_observed(polls, result.is_ready()),
                    Err(ResponsivenessRefusal::GoalNotObserved),
                    "same checker refuses a mislabeled live wait"
                );
                assert_eq!(notify.waiter_count(), 1);
            }
            assert_eq!(
                cx.checkpoint_state().checkpoint_count,
                before,
                "actual missing checkpoint, not a case label"
            );
            assert_eq!(
                ResponsivenessRegistry::lookup("sync::Notify::notified")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            assert!(notify.notify_one());
            assert_eq!(poll(wait.as_mut()), Poll::Ready(()));
            drop(wait);
            assert_eq!(notify.waiter_count(), 0);
        }
        {
            let (cx, _clock, timer) = timer_context();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let gate = Arc::new(Notify::new());
            let factory_gate = Arc::clone(&gate);
            let pool = GenericPool::new(
                move || {
                    let gate = Arc::clone(&factory_gate);
                    async move {
                        gate.notified().await;
                        Ok::<_, std::io::Error>(53_u8)
                    }
                },
                PoolConfig::with_max_size(1),
            );
            let mut acquire = pool.acquire(&cx);
            assert!(poll(acquire.as_mut()).is_pending());
            assert_eq!(
                gate.waiter_count(),
                1,
                "actual factory owns the blocked notification"
            );
            assert_eq!(pool.stats().total, 1, "real creating slot is retained");
            // TimeoutFuture itself polls Sleep: User cancellation can finish
            // that sleep. Deadline/Timeout cancellation deliberately cannot,
            // so use the actual kind which makes this a nonprogress witness.
            cx.cancel_with(
                CancelKind::Timeout,
                Some("factory still needs input or actual timer progress"),
            );
            let before = cx.checkpoint_state().checkpoint_count;
            for _ in 0..3 {
                assert!(poll(acquire.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert_eq!(gate.waiter_count(), 1);
            assert_eq!(
                ResponsivenessRegistry::lookup("sync::Pool::acquire")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::Timeout)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            drop(acquire);
            assert_eq!(
                gate.waiter_count(),
                0,
                "real factory future retired by owner"
            );
            assert_eq!(pool.stats().total, 0, "creating slot rollback");
            assert_eq!(timer.pending_count(), 0);
            assert!(poll(pool.close().as_mut()).is_ready());
        }
        {
            let cx = Cx::for_testing();
            let cell = OnceCell::new();
            let gate = Notify::new();
            let mut initialize = Box::pin(cell.get_or_init(|| async {
                gate.notified().await;
                59_u8
            }));
            assert!(poll(initialize.as_mut()).is_pending());
            assert_eq!(gate.waiter_count(), 1);
            cx.cancel_with(
                CancelKind::User,
                Some("initializer owns independent progress"),
            );
            let before = cx.checkpoint_state().checkpoint_count;
            for _ in 0..3 {
                assert!(poll(initialize.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert_eq!(
                ResponsivenessRegistry::lookup("once-cell.initialize")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            assert!(!cell.is_initialized());
            assert!(gate.notify_one());
            assert_eq!(poll(initialize.as_mut()), Poll::Ready(&59));
            drop(initialize);
            assert_eq!(gate.waiter_count(), 0);
            assert_eq!(cell.get(), Some(&59));
        }
        {
            let cx = Cx::for_testing();
            let _ambient = Cx::set_current(Some(cx.clone()));
            let (mut writer, state) = ControlledIo::new();
            let mut permit = crate::io::WritePermit::new(&mut writer);
            permit.stage(b"real staged commit");
            let mut commit = Box::pin(permit.commit());
            assert!(poll(commit.as_mut()).is_pending());
            assert!(state.lock().waiter.is_some());
            cx.cancel_with(CancelKind::User, Some("generic commit does not checkpoint"));
            let before = cx.checkpoint_state().checkpoint_count;
            for _ in 0..3 {
                assert!(poll(commit.as_mut()).is_pending());
            }
            assert_eq!(cx.checkpoint_state().checkpoint_count, before);
            assert!(state.lock().bytes.is_empty());
            assert_eq!(
                ResponsivenessRegistry::lookup("io::WritePermit::commit")
                    .unwrap()
                    .bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::for_cx(&cx, CancelKind::User)
                    ),
                Err(ResponsivenessRefusal::ExternalProgress)
            );
            release_writes(&state);
            assert!(matches!(poll(commit.as_mut()), Poll::Ready(Ok(()))));
            drop(commit);
            assert_eq!(state.lock().bytes, b"real staged commit");
            assert!(state.lock().waiter.is_none());
        }
    }

    #[test]
    fn responsiveness_inventory_refuses_unknown_unbounded_and_owner_claims() {
        let cx = Cx::for_testing();
        let query = ResponsivenessQuery::for_cx(&cx, CancelKind::User);
        let mut aliases = std::collections::BTreeSet::new();
        let mut finite = 0;
        let mut refused = 0;
        for entry in ResponsivenessRegistry::entries() {
            assert_eq!(
                ResponsivenessRegistry::lookup(entry.id()).unwrap().id(),
                entry.id()
            );
            assert!(!entry.source().is_empty());
            assert!(!entry.contract().is_empty());
            for alias in entry.aliases() {
                assert!(aliases.insert(*alias), "duplicate inventory alias {alias}");
                assert_eq!(
                    ResponsivenessRegistry::lookup(alias).unwrap().id(),
                    entry.id()
                );
            }
            assert_eq!(
                entry.bound(ResponsivenessGoal::OwnerQuiescent, query),
                Err(ResponsivenessRefusal::OwnerProgress)
            );
            if let ResponsivenessRule::Refuse(reason) = entry.rule {
                refused += 1;
                assert_eq!(
                    entry.bound(ResponsivenessGoal::OperationReturned, query),
                    Err(reason)
                );
                assert_eq!(
                    entry.bound(ResponsivenessGoal::CancellationObserved, query),
                    Err(reason)
                );
            } else {
                finite += 1;
                assert_eq!(
                    entry.bound(
                        ResponsivenessGoal::OperationReturned,
                        ResponsivenessQuery::without_context(CancelKind::User)
                    ),
                    Err(ResponsivenessRefusal::MissingContext)
                );
            }
        }
        assert!(finite > 0 && refused > 0);
        assert_eq!(
            ResponsivenessRegistry::lookup("sync::Mutex::hypothetical_wait").unwrap_err(),
            ResponsivenessRefusal::UnknownOperation,
            "finite families cannot confer bounds on unknown methods"
        );
        assert_eq!(
            ResponsivenessRegistry::lookup("io::AsyncReadExt::read_exact")
                .unwrap()
                .bound(ResponsivenessGoal::OperationReturned, query),
            Err(ResponsivenessRefusal::ExternalProgress)
        );
        assert_eq!(
            ResponsivenessRegistry::lookup("channel::partition::PartitionedSender::send")
                .unwrap()
                .bound(ResponsivenessGoal::OperationReturned, query),
            Err(ResponsivenessRefusal::ExternalProgress)
        );
        assert_eq!(
            ResponsivenessRegistry::lookup("unknown::wait").unwrap_err(),
            ResponsivenessRefusal::UnknownOperation
        );
        for (alias, entry) in [
            ("net::UdpSocket::poll_peek_from", "net.udp-wait"),
            ("net::TcpStream::poll_read_vectored", "net.tcp-wait"),
            ("net::TcpStream::poll_flush", "net.tcp-wait"),
            ("net::TcpStream::poll_shutdown", "net.tcp-wait"),
            ("channel::oneshot::SendPermit::abort", "channel.commit"),
            ("channel::session::TrackedPermit::abort", "channel.commit"),
            (
                "channel::session::TrackedOneshotPermit::abort",
                "channel.commit",
            ),
            (
                "sync::OwnedSemaphorePermit::try_acquire_arc_checked",
                "sync.synchronous",
            ),
            ("sync::OwnedSemaphorePermit::forget", "sync.synchronous"),
            ("sync::OwnedRwLockWriteGuard::downgrade", "sync.synchronous"),
            ("sync::OwnedRwLockReadGuard::try_read", "sync.synchronous"),
            ("sync::OwnedMappedMutexGuard::try_map", "sync.synchronous"),
            ("sync::OwnedMutexGuard::lock", "mutex.lock"),
            (
                "sync::OwnedSemaphorePermit::acquire_checked#zero",
                "semaphore.zero",
            ),
            ("io::read_line", "io.buffered"),
            ("io::ReadU8", "io.generic"),
            ("io::ext::ReadU64Le", "io.generic"),
            ("Cx::race_drained_timeout_named", "structured.drain"),
            ("Cx::open_child_region", "structured.drain"),
        ] {
            assert_eq!(
                ResponsivenessRegistry::lookup(alias).unwrap().id(),
                entry,
                "{alias}"
            );
        }
        assert_eq!(
            ResponsivenessRegistry::lookup("Cx::masked")
                .unwrap()
                .bound(ResponsivenessGoal::OperationReturned, query),
            Err(ResponsivenessRefusal::UnboundedMaskBody)
        );
        println!(
            "ASUPERSYNC_RESPONSIVENESS_INVENTORY {}",
            serde_json::json!({
                "entries": finite + refused, "conditional_finite_phases": finite,
                "refused_phases": refused, "aliases": aliases.len(),
                "scope": "classification_and_arithmetic_not_behavioral_completeness"
            })
        );
    }
