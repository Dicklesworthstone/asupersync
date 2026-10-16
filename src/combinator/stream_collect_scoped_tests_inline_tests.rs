    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::channel::{mpsc, oneshot};
    use crate::cx::ChildRegion;
    use crate::lab::run_async_under_lab;
    use crate::runtime::spawn_mailbox::{RegionCommand, RegisterRegionFinalizer};
    use crate::runtime::{TaskHandle, yield_now};
    use crate::stream::iter;
    use crate::sync::Notify;
    use std::future::poll_fn;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Progress {
        holding: AtomicBool,
        finished: AtomicUsize,
        changed: Notify,
    }

    async fn descendant(
        cx: Cx,
        sender: mpsc::Sender<()>,
        progress: Arc<Progress>,
        panic_after_cleanup: bool,
    ) {
        let permit = sender.reserve_checked(&cx).await.unwrap();
        progress.holding.store(true, Ordering::SeqCst);
        progress.changed.notify_waiters();
        cx.cancelled().await;
        // Neither handle destruction nor an immediate return can stand in for
        // the asynchronous cleanup that the outer operation must wait for.
        yield_now().await;
        yield_now().await;
        drop(permit);
        progress.finished.fetch_add(1, Ordering::SeqCst);
        if panic_after_cleanup {
            panic!("scoped descendant cleanup panic");
        }
    }

    async fn subtree_journey(cx: Cx, fail: bool, panic_descendant: bool) {
        let progress = Arc::new(Progress::default());
        let regions: Arc<Mutex<Vec<ChildRegion>>> = Arc::new(Mutex::new(Vec::new()));
        let retained: Arc<Mutex<Vec<TaskHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let (sender, mut receiver) = mpsc::channel(1);
        let outer_region = cx.region_id();
        let unrelated_done = Arc::new(AtomicBool::new(false));
        let observe_unrelated = Arc::clone(&unrelated_done);
        let mut unrelated = cx.spawn(move |child| async move {
            child.cancelled().await;
            observe_unrelated.store(true, Ordering::SeqCst);
        }).unwrap();
        let observe = Arc::clone(&progress);
        let keep_regions = Arc::clone(&regions);
        let keep_handles = Arc::clone(&retained);
        let send = sender.clone();
        let result = try_for_each_concurrent_scoped(
            &cx,
            iter(0..if fail { 2 } else { 1 }),
            2,
            move |child, index| {
                let progress = Arc::clone(&observe);
                let regions = Arc::clone(&keep_regions);
                let retained = Arc::clone(&keep_handles);
                let sender = send.clone();
                async move {
                    assert_ne!(child.region_id(), outer_region, "work has its own boundary");
                    if index == 1 {
                        progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                        return Err("item failure");
                    }
                    let nested = child.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                    let mut handle = nested.cx().spawn({
                        let progress = Arc::clone(&progress);
                        move |grandchild| descendant(grandchild, sender, progress, panic_descendant)
                    }).unwrap();
                    progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                    if fail {
                        // The direct item cannot finish until its descendant
                        // gets REGION cancellation. A direct-task-only abort
                        // followed by joining this item would deadlock here.
                        let _ = poll_fn(|task| handle.poll_join(task)).await;
                        drop(nested);
                    } else {
                        // Retain both handles outside the item so their Drop
                        // cannot accidentally satisfy the subtree-close claim.
                        retained.lock().push(handle);
                        regions.lock().push(nested);
                    }
                    Ok(())
                }
            },
        ).await;
        if panic_descendant {
            assert!(matches!(result, Outcome::Panicked(ref p) if format!("{p:?}").contains("scoped descendant cleanup panic")));
        } else if fail {
            assert!(matches!(result, Outcome::Err(ScopedStreamError::Item("item failure"))));
        } else {
            assert!(matches!(result, Outcome::Ok(())), "{result:?}");
        }
        assert!(progress.holding.load(Ordering::SeqCst), "non-vacuous checked permit witness");
        assert_eq!(progress.finished.load(Ordering::SeqCst), 1, "before parent region closes");
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
        sender.try_reserve().unwrap().abort();
        for handle in retained.lock().iter_mut() {
            assert!(!matches!(handle.try_join(), Ok(None)), "descendant actually retired");
        }
        assert!(!unrelated_done.load(Ordering::SeqCst), "parent sibling was not cancelled");
        unrelated.abort();
        let _ = unrelated.join(&cx).await;
        assert!(unrelated_done.load(Ordering::SeqCst));
        drop(regions);
    }

    #[test]
    fn scoped_success_and_failure_drain_nested_descendants_under_lab() {
        for fail in [false, true] {
            let ((), report) = run_async_under_lab(0x5C010, move |cx| subtree_journey(cx, fail, false));
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_descendant_panic_is_not_hidden_by_successful_item() {
        let ((), report) = run_async_under_lab(0x5C011, |cx| subtree_journey(cx, false, true));
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn scoped_subtree_barrier_runs_on_native_runtime() {
        for fail in [false, true] {
            let passed = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&passed);
            let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                crate::time::timeout(
                    cx.now(),
                    std::time::Duration::from_secs(10),
                    subtree_journey(cx, fail, false),
                ).await.expect("scoped subtree drain timed out");
                observed.store(true, Ordering::SeqCst);
            }));
            assert!(passed.load(Ordering::SeqCst), "native body reached all post-return assertions");
        }
    }

    #[test]
    fn scoped_finalizer_runs_before_return_and_its_panic_is_reported() {
        for panic_finalizer in [false, true] {
            let ((), report) = run_async_under_lab(0x5C012, move |cx| async move {
                let finalized = Arc::new(AtomicUsize::new(0));
                let observe = Arc::clone(&finalized);
                let outcome = for_each_concurrent_scoped(&cx, iter([()]), 1, move |child, ()| {
                    let finalized = Arc::clone(&observe);
                    async move {
                        let (ack, mut acknowledged) = oneshot::channel();
                        let request = RegisterRegionFinalizer::new(child.region_id(), move || {
                            finalized.fetch_add(1, Ordering::SeqCst);
                            if panic_finalizer { panic!("scoped finalizer panic"); }
                        }, ack);
                        child.spawn_gateway_handle().unwrap()
                            .enqueue_region_command(RegionCommand::RegisterFinalizer(request)).unwrap();
                        acknowledged.recv_uninterruptible().await.unwrap().unwrap();
                    }
                }).await;
                assert_eq!(finalized.load(Ordering::SeqCst), 1);
                if panic_finalizer {
                    assert!(matches!(outcome, Outcome::Panicked(ref p) if format!("{p:?}").contains("scoped finalizer panic")));
                } else {
                    assert!(matches!(outcome, Outcome::Ok(())), "{outcome:?}");
                }
            });
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_cancellation_and_abandonment_close_the_subtree() {
        for abandon in [false, true] {
            let ((), report) = run_async_under_lab(0x5C013, move |cx| async move {
                let progress = Arc::new(Progress::default());
                let (sender, _receiver) = mpsc::channel(1);
                let observe = Arc::clone(&progress);
                let send = sender.clone();
                let returned = Arc::new(AtomicBool::new(false));
                let did_return = Arc::clone(&returned);
                let mut driver = cx.spawn(move |owner| async move {
                    let signal = Arc::clone(&observe);
                    let mut work = Box::pin(try_for_each_concurrent_scoped(
                        &owner, iter([()]), 1, move |item_cx, ()| {
                            let progress = Arc::clone(&observe);
                            let sender = send.clone();
                            async move {
                                let mut nested = item_cx.spawn(move |child| descendant(child, sender, progress, false)).unwrap();
                                let _ = poll_fn(|task| nested.poll_join(task)).await;
                                Ok::<(), ()>(())
                            }
                        },
                    ));
                    if abandon {
                        let mut ready = std::pin::pin!(signal.changed.wait_until(|| {
                            signal.holding.load(Ordering::SeqCst)
                        }));
                        poll_fn(|task| {
                            assert!(work.as_mut().poll(task).is_pending());
                            ready.as_mut().poll(task)
                        }).await;
                        drop(work);
                    } else {
                        let result = work.as_mut().await;
                        assert!(matches!(result, Outcome::Cancelled(_)));
                        assert_eq!(signal.finished.load(Ordering::SeqCst), 1);
                    }
                    did_return.store(true, Ordering::SeqCst);
                }).unwrap();
                progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                if !abandon { driver.abort(); }
                let _ = driver.join(&cx).await;
                assert!(returned.load(Ordering::SeqCst));
                for _ in 0..256 {
                    if progress.finished.load(Ordering::SeqCst) == 1 { break; }
                    yield_now().await;
                }
                assert_eq!(progress.finished.load(Ordering::SeqCst), 1);
                assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
            });
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_refusal_does_not_poll_source_or_invoke_factory() {
        let cx = Cx::for_testing();
        let polls = std::cell::Cell::new(0);
        let source = iter([()]).inspect(|_| polls.set(polls.get() + 1));
        let mut work = Box::pin(for_each_concurrent_scoped(&cx, source, 1, |_, ()| async {
            panic!("refused factory must not run");
        }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Err(ScopedStreamError::Region(_)))));
        drop(work);
        assert_eq!(polls.get(), 0);
    }

    async fn scoped_collection_journey(cx: Cx) {
        struct Value(usize); // Deliberately not Clone.
        let progress: Arc<Vec<Arc<Progress>>> = Arc::new(
            (0..4).map(|_| Arc::new(Progress::default())).collect(),
        );
        let retained: Arc<Mutex<Vec<TaskHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let (sender, _receiver) = mpsc::channel(4);
        let signals = Arc::clone(&progress);
        let keep = Arc::clone(&retained);
        let later_completed = Arc::clone(&completed);
        let send = sender.clone();
        let outcome = map_collect_concurrent_scoped(&cx, iter(0..4), 2, move |child, index| {
            let progress = Arc::clone(&signals[index]);
            let keep = Arc::clone(&keep);
            let completed = Arc::clone(&later_completed);
            let sender = send.clone();
            async move {
                let handle = child.spawn({
                    let progress = Arc::clone(&progress);
                    move |desc| descendant(desc, sender, progress, false)
                }).unwrap();
                progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                keep.lock().push(handle);
                if index == 0 {
                    while completed.load(Ordering::SeqCst) == 0 { yield_now().await; }
                }
                completed.fetch_add(1, Ordering::SeqCst);
                Value(index * 10)
            }
        }).await;
        let Outcome::Ok(values) = outcome else { panic!("scoped collection failed") };
        assert_eq!(values.into_iter().map(|value| value.0).collect::<Vec<_>>(), [0, 10, 20, 30]);
        assert_eq!(completed.load(Ordering::SeqCst), 4);
        assert!(progress.iter().all(|p| p.holding.load(Ordering::SeqCst)));
        assert!(progress.iter().all(|p| p.finished.load(Ordering::SeqCst) == 1));
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        for handle in retained.lock().iter_mut() {
            assert!(!matches!(handle.try_join(), Ok(None)), "all descendants retired before output");
        }
    }

    #[test]
    fn scoped_collection_preserves_order_and_drains_every_descendant() {
        for seed in [0x5C014, 0x5C015] {
            let ((), report) = run_async_under_lab(seed, scoped_collection_journey);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn scoped_ordered_collection_has_a_native_cleanup_barrier() {
        let passed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&passed);
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            crate::time::timeout(cx.now(), std::time::Duration::from_secs(10),
                scoped_collection_journey(cx)).await.expect("scoped collection timed out");
            observed.store(true, Ordering::SeqCst);
        }));
        assert!(passed.load(Ordering::SeqCst));
    }

    #[test]
    fn scoped_outputs_are_discarded_only_after_failed_subtree_cleanup() {
        struct Value {
            progress: Arc<Progress>,
            finalized: Arc<AtomicBool>,
            early: Arc<AtomicBool>,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Value {
            fn drop(&mut self) {
                if self.progress.finished.load(Ordering::SeqCst) != 1
                    || !self.finalized.load(Ordering::SeqCst)
                {
                    self.early.store(true, Ordering::SeqCst);
                }
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        for panic_finalizer in [false, true] {
            let ((), report) = run_async_under_lab(0x5C016, move |cx| async move {
                let progress = Arc::new(Progress::default());
                let finalized = Arc::new(AtomicBool::new(false));
                let early = Arc::new(AtomicBool::new(false));
                let drops = Arc::new(AtomicUsize::new(0));
                let value_ready = Arc::new(AtomicBool::new(false));
                let changed = Arc::new(Notify::new());
                let retained = Arc::new(Mutex::new(None));
                let (sender, _receiver) = mpsc::channel(1);
                let signals = (Arc::clone(&progress), Arc::clone(&finalized),
                    Arc::clone(&early), Arc::clone(&drops), Arc::clone(&retained));
                let outcome = try_map_collect_concurrent_scoped(
                    &cx, iter(0..if panic_finalizer { 1 } else { 2 }), 2,
                    move |child, index| {
                        let (progress, finalized, early, drops, retained) = signals.clone();
                        let sender = sender.clone();
                        let ready = Arc::clone(&value_ready);
                        let changed = Arc::clone(&changed);
                        async move {
                            if index == 1 {
                                changed.wait_until(|| ready.load(Ordering::SeqCst)).await;
                                return Err("scoped map failed");
                            }
                            let handle = child.spawn({
                                let progress = Arc::clone(&progress);
                                move |desc| descendant(desc, sender, progress, false)
                            }).unwrap();
                            *retained.lock() = Some(handle);
                            progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                            let (ack, mut acknowledged) = oneshot::channel();
                            let finish = Arc::clone(&finalized);
                            let request = RegisterRegionFinalizer::new(child.region_id(), move || {
                                finish.store(true, Ordering::SeqCst);
                                if panic_finalizer { panic!("collected value finalizer failed"); }
                            }, ack);
                            child.spawn_gateway_handle().unwrap()
                                .enqueue_region_command(RegionCommand::RegisterFinalizer(request)).unwrap();
                            acknowledged.recv_uninterruptible().await.unwrap().unwrap();
                            let value = Value { progress, finalized, early, drops };
                            ready.store(true, Ordering::SeqCst);
                            changed.notify_waiters();
                            Ok(value)
                        }
                    },
                ).await;
                if panic_finalizer {
                    assert!(matches!(outcome, Outcome::Panicked(_)));
                } else {
                    assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item("scoped map failed"))));
                }
                assert_eq!(progress.finished.load(Ordering::SeqCst), 1);
                assert!(finalized.load(Ordering::SeqCst));
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert!(!early.load(Ordering::SeqCst), "output survived through descendant and finalizer cleanup");
                assert!(!matches!(retained.lock().as_mut().unwrap().try_join(), Ok(None)));
            });
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_source_panic_cancels_descendants_before_waiting_for_their_parent() {
        let ((), report) = run_async_under_lab(0x5C017, |cx| async move {
            let progress = Arc::new(Progress::default());
            let source_signal = Arc::clone(&progress);
            let source = iter([0, 1]).then(move |index| {
                let progress = Arc::clone(&source_signal);
                Box::pin(async move {
                    if index == 1 {
                        progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                        panic!("scoped source failed with a parked subtree");
                    }
                })
            });
            let (sender, _receiver) = mpsc::channel(1);
            let child_signal = Arc::clone(&progress);
            let outcome = try_map_collect_concurrent_scoped(&cx, source, 2, move |item, ()| {
                let progress = Arc::clone(&child_signal);
                let sender = sender.clone();
                async move {
                    let mut nested = item.spawn(move |desc| descendant(desc, sender, progress, false)).unwrap();
                    let _ = poll_fn(|task| nested.poll_join(task)).await;
                    Ok::<_, ()>(7)
                }
            }).await;
            assert!(matches!(outcome, Outcome::Panicked(ref p) if format!("{p:?}").contains("scoped source failed")));
            assert!(progress.holding.load(Ordering::SeqCst));
            assert_eq!(progress.finished.load(Ordering::SeqCst), 1);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn scoped_collection_pre_cancel_refuses_before_source_poll() {
        let cx = Cx::for_testing();
        cx.cancel_fast(crate::types::CancelKind::User);
        let polls = std::cell::Cell::new(0);
        let source = iter([7]).inspect(|_| polls.set(polls.get() + 1));
        let mut work = Box::pin(map_collect_concurrent_scoped(&cx, source, 1,
            |_child, item| async move { item }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Cancelled(_))));
        drop(work);
        assert_eq!(polls.get(), 0);
    }

    /// An owner cancelled while an item runs gets its own reason back, as it
    /// does when cancelled before the call. The stream driver used to report
    /// that case as a generic User cancellation.
    #[test]
    fn scoped_owner_cancelled_mid_run_gets_its_own_reason() {
        let ((), report) = run_async_under_lab(0x5C016, |cx| async move {
            let parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = Arc::new(Mutex::new(None));
            let (park, record) = (Arc::clone(&parked), Arc::clone(&observed));
            let mut driver = cx
                .spawn(move |owner| async move {
                    let result = try_for_each_concurrent_scoped(
                        &owner,
                        iter([()]),
                        1,
                        move |item_cx, ()| {
                            let parked = Arc::clone(&park);
                            async move {
                                parked.store(true, Ordering::SeqCst);
                                item_cx.cancelled().await;
                                Ok::<(), ()>(())
                            }
                        },
                    )
                    .await;
                    *record.lock() = Some(match result {
                        Outcome::Cancelled(reason) => Ok(reason.kind()),
                        other => Err(format!("{other:?}")),
                    });
                })
                .unwrap();
            while !parked.load(Ordering::SeqCst) {
                yield_now().await;
            }
            driver.abort_with_reason(crate::types::CancelReason::new(
                crate::types::CancelKind::Shutdown,
            ));
            let _ = driver.join(&cx).await;
            assert_eq!(
                observed.lock().take(),
                Some(Ok(crate::types::CancelKind::Shutdown)),
                "the owner's own reason, not the driver's generic one"
            );
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
