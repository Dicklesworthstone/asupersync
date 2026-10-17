    use super::*;
    use crate::channel::mpsc::{self, RecvError};
    use crate::lab::run_async_under_lab;
    use crate::runtime::yield_now;
    use crate::stream::iter;
    use crate::sync::{OwnedSemaphorePermit, Semaphore};
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake, Waker};

    #[derive(Debug)]
    struct Value {
        index: usize,
        live: Arc<AtomicUsize>,
    }

    impl Value {
        fn new(index: usize, live: Arc<AtomicUsize>) -> Self {
            live.fetch_add(1, Ordering::SeqCst);
            Self { index, live }
        }
    }

    impl Drop for Value {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    async fn turns() {
        for _ in 0..32 { yield_now().await; }
    }

    async fn ordered_pressure(cx: Cx) {
        const LIMIT: usize = 4;
        const CAPACITY: usize = 2;
        const ITEMS: usize = 41;
        let (sender, mut receiver) = mpsc::channel(CAPACITY);
        let destination = sender.clone();
        let release_head = Arc::new(Semaphore::new(0));
        let head_gate = Arc::clone(&release_head);
        let live = Arc::new(AtomicUsize::new(0));
        let mapper_live = Arc::clone(&live);
        let reads = Arc::new(AtomicUsize::new(0));
        let source_reads = Arc::clone(&reads);
        let polls = Arc::new(AtomicUsize::new(0));
        let driver_polls = Arc::clone(&polls);
        let mut producer = cx.spawn(move |child| async move {
            let source = iter(0..ITEMS).inspect(move |_| {
                source_reads.fetch_add(1, Ordering::SeqCst);
            });
            let mut work = Box::pin(try_map_send_ordered_concurrent_scoped(
                &child, source, LIMIT, &destination,
                move |mapper, index| {
                    let gate = Arc::clone(&head_gate);
                    let live = Arc::clone(&mapper_live);
                    async move {
                        if index == 0 {
                            let _permit = OwnedSemaphorePermit::acquire(gate, &mapper, 1)
                                .await.map_err(|_| "head cancelled")?;
                        }
                        Ok::<_, &'static str>(Value::new(index, live))
                    }
                },
            ));
            poll_fn(|task| {
                driver_polls.fetch_add(1, Ordering::SeqCst);
                work.as_mut().poll(task)
            }).await
        }).unwrap();

        let mut staged = false;
        for _ in 0..10_000 {
            if live.load(Ordering::SeqCst) == LIMIT - 1 {
                staged = true;
                break;
            }
            yield_now().await;
        }
        assert!(staged, "later mappers must finish while the head is blocked");
        assert!(receiver.is_empty(), "no successor can bypass the blocked first input");
        assert_eq!(reads.load(Ordering::SeqCst), LIMIT);
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        turns().await;
        let before = polls.load(Ordering::SeqCst);
        turns().await;
        assert_eq!(polls.load(Ordering::SeqCst), before);
        assert_eq!(reads.load(Ordering::SeqCst), LIMIT, "no unbounded reorder read-ahead");

        release_head.add_permits(1);
        let mut full = false;
        for _ in 0..10_000 {
            if receiver.len() == CAPACITY
                && live.load(Ordering::SeqCst) == CAPACITY + LIMIT
                && sender.telemetry_snapshot(1).send_waiter_count == 1
            {
                full = true;
                break;
            }
            yield_now().await;
        }
        assert!(full, "destination pressure must retain the remaining task slots");
        assert_eq!(reads.load(Ordering::SeqCst), CAPACITY + LIMIT);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1,
            "only the head output may wait for channel capacity");
        for index in 0..ITEMS {
            let value = receiver.recv(&cx).await.unwrap();
            assert_eq!(value.index, index);
            drop(value);
        }
        assert!(matches!(producer.join(&cx).await, Ok(Outcome::Ok(()))));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
    }

    #[test]
    fn ordered_publication_bounds_reorder_and_destination_pressure_in_lab() {
        for seed in [0x5E10, 0x5E11, 0x5E12] {
            let ((), report) = run_async_under_lab(seed, ordered_pressure);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn ordered_publication_bounds_reorder_and_destination_pressure_on_native_runtime() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            ordered_pressure(Cx::current().unwrap()).await;
        }));
    }

    #[test]
    fn later_map_failure_does_not_wait_for_its_output_turn_or_publish_a_suffix() {
        let ((), report) = run_async_under_lab(0x5E13, |cx| async move {
            let (sender, mut receiver) = mpsc::channel(4);
            let head_started = Arc::new(Published::default());
            let tail_mapped = Arc::new(Published::default());
            let cleaned = Arc::new(AtomicUsize::new(0));
            let map_cleaned = Arc::clone(&cleaned);
            let live = Arc::new(AtomicUsize::new(0));
            let map_live = Arc::clone(&live);
            let outcome = try_map_send_ordered_concurrent_scoped(
                &cx, iter(0..3), 3, &sender,
                move |child, index| {
                    let head = Arc::clone(&head_started);
                    let tail = Arc::clone(&tail_mapped);
                    let cleaned = Arc::clone(&map_cleaned);
                    let live = Arc::clone(&map_live);
                    async move {
                        match index {
                            0 => {
                                head.publish();
                                child.cancelled().await;
                                yield_now().await;
                                cleaned.fetch_add(1, Ordering::SeqCst);
                                Err("head drained")
                            }
                            1 => {
                                assert!(head.wait(&child).await);
                                assert!(tail.wait(&child).await);
                                Err("middle mapper failed")
                            }
                            _ => {
                                let value = Value::new(index, live);
                                tail.publish();
                                Ok(value)
                            }
                        }
                    }
                },
            ).await;
            assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item(
                StreamSendError::Map("middle mapper failed")))));
            assert_eq!(cleaned.load(Ordering::SeqCst), 1, "joined before caller region close");
            assert_eq!(live.load(Ordering::SeqCst), 0, "staged successor was discarded");
            assert!(matches!(receiver.try_recv(), Err(RecvError::Empty)));
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    async fn cancellation_drains(cx: Cx) {
        let (sender, mut receiver) = mpsc::channel(1);
        sender.try_send(usize::MAX).unwrap();
        let destination = sender.clone();
        let (resource, resource_receiver) = mpsc::channel::<()>(1);
        let descendant_resource = resource.clone();
        let holding = Arc::new(AtomicBool::new(false));
        let descendant_holding = Arc::clone(&holding);
        let cleaned = Arc::new(AtomicUsize::new(0));
        let descendant_cleaned = Arc::clone(&cleaned);
        let at_return = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&at_return);
        let observed_cleaned = Arc::clone(&cleaned);
        let handles = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let retained = Arc::clone(&handles);
        let prepared = Arc::new(AtomicUsize::new(0));
        let mapped = Arc::clone(&prepared);
        let mut producer = cx.spawn(move |child| async move {
            let outcome = try_map_send_ordered_concurrent_scoped(
                &child, iter([0, 1]), 2, &destination,
                move |mapper, index| {
                    let resource = descendant_resource.clone();
                    let holding = Arc::clone(&descendant_holding);
                    let cleaned = Arc::clone(&descendant_cleaned);
                    let handles = Arc::clone(&retained);
                    let prepared = Arc::clone(&mapped);
                    async move {
                        if index == 0 {
                            let handle = mapper.spawn(move |grandchild| async move {
                                let permit = resource.reserve_checked(&grandchild).await.unwrap();
                                holding.store(true, Ordering::SeqCst);
                                grandchild.cancelled().await;
                                yield_now().await;
                                yield_now().await;
                                drop(permit);
                                cleaned.fetch_add(1, Ordering::SeqCst);
                            }).unwrap();
                            // A retained join cannot provide accidental drop cancellation.
                            handles.lock().push(handle);
                        }
                        prepared.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &'static str>(index)
                    }
                },
            ).await;
            assert!(outcome.is_cancelled());
            observed.store(observed_cleaned.load(Ordering::SeqCst), Ordering::SeqCst);
        }).unwrap();

        let mut parked = false;
        for _ in 0..10_000 {
            if prepared.load(Ordering::SeqCst) == 2
                && holding.load(Ordering::SeqCst)
                && sender.telemetry_snapshot(1).send_waiter_count == 1
            {
                parked = true;
                break;
            }
            yield_now().await;
        }
        assert!(parked, "head output, successor and resource-owning descendant must be pending");
        assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 1);
        producer.abort();
        let joined = producer.join(&cx).await;
        assert!(matches!(joined, Ok(()) | Err(crate::runtime::JoinError::Cancelled(_))));
        assert_eq!(at_return.load(Ordering::SeqCst), 1, "subtree was drained before return");
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        resource.try_reserve().unwrap().abort();
        assert_eq!(receiver.try_recv(), Ok(usize::MAX));
        assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
        assert!(handles.lock().iter().all(|handle| handle.is_finished()));
        drop(resource_receiver);
    }

    #[test]
    fn cancellation_drains_order_waiters_and_checked_descendants_in_lab() {
        let ((), report) = run_async_under_lab(0x5E14, cancellation_drains);
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn cancellation_drains_order_waiters_and_checked_descendants_on_native_runtime() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            cancellation_drains(Cx::current().unwrap()).await;
        }));
    }

    #[test]
    fn checked_admission_refusal_keeps_output_without_publishing() {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        let ((), report) = run_async_under_lab(0x5E15, |cx| async move {
            let (sender, mut receiver) = mpsc::channel(1);
            let outcome = try_map_send_ordered_concurrent_scoped(
                &cx, iter([7]), 1, &sender,
                |child, value| async move {
                    // Private fault injection: the mapper is still a real task,
                    // but its checked-send admission capability has been revoked.
                    child.revoke_obligation_admission();
                    Ok::<_, ()>(Box::new(value))
                },
            ).await;
            assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item(
                StreamSendError::Delivery(CheckedSendError::Admission {
                    error: ObligationAdmissionError::HolderNotLive, value,
                })
            )) if *value == 7));
            assert!(matches!(receiver.try_recv(), Err(RecvError::Empty)));
            assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn order_wait_migrates_wakers_and_cleans_up_on_cancellation_or_drop() {
        for cancel in [false, true] {
            let cx = Cx::for_testing();
            let gate = Published::default();
            let first = Arc::new(Wakes::default());
            let second = Arc::new(Wakes::default());
            let first_waker = Waker::from(Arc::clone(&first));
            let second_waker = Waker::from(Arc::clone(&second));
            let mut first_task = Context::from_waker(&first_waker);
            let mut second_task = Context::from_waker(&second_waker);
            let mut waiting = Box::pin(gate.wait(&cx));
            assert!(waiting.as_mut().poll(&mut first_task).is_pending());
            assert!(waiting.as_mut().poll(&mut second_task).is_pending());
            assert_eq!(Arc::strong_count(&first), 2);
            if cancel {
                cx.cancel_fast(crate::types::CancelKind::User);
                assert_eq!(first.0.load(Ordering::SeqCst), 0);
                assert!(second.0.load(Ordering::SeqCst) > 0);
                assert_eq!(waiting.as_mut().poll(&mut second_task), Poll::Ready(false));
                assert_eq!(gate.changed.waiter_count(), 0);
                assert_eq!(Arc::strong_count(&second), 2);
            }
            drop(waiting);
            assert_eq!(gate.changed.waiter_count(), 0);
            assert_eq!(Arc::strong_count(&second), 2);
        }
    }

    #[test]
    fn completed_predecessor_is_not_lost_before_or_after_wait_registration() {
        for prepublished in [false, true] {
            let cx = Cx::for_testing();
            let gate = Published::default();
            let count = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut task = Context::from_waker(&waker);
            if prepublished { gate.publish(); }
            let mut wait = Box::pin(gate.wait(&cx));
            if !prepublished {
                assert!(wait.as_mut().poll(&mut task).is_pending());
                gate.publish();
                assert!(count.0.load(Ordering::SeqCst) > 0);
            }
            assert_eq!(wait.as_mut().poll(&mut task), Poll::Ready(true));
            assert_eq!(gate.changed.waiter_count(), 0);
            assert_eq!(Arc::strong_count(&count), 2);
        }
    }
