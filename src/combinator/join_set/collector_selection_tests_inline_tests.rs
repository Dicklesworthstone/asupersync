    use super::*;
    use super::super::MemberWake;
    use crate::channel::oneshot;
    use crate::cx::{Cx, Scope};
    use crate::runtime::{JoinError, TaskHandle};
    use crate::types::policy::FailFast;
    use crate::types::{Budget, CancelKind, RegionId, TaskId};
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake};

    type Sender = oneshot::Sender<Result<Result<u16, &'static str>, JoinError>>;

    fn member(slot: u32) -> (Sender, TaskHandle<Result<u16, &'static str>>) {
        let (send, receive) = oneshot::channel();
        let handle = TaskHandle::new(TaskId::new_for_test(slot, 0), receive, std::sync::Weak::new());
        (send, handle)
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn public_quorum_counts_pending_and_ready_candidates_in_one_quantum() {
        for ready_error in [false, true] {
            let cx = Cx::for_testing();
            let scope = Scope::<FailFast>::new(RegionId::new_for_test(1, 0), Budget::INFINITE);
            let mut set = JoinSet::new(&scope);
            let mut senders = Vec::new();
            for index in 0..130 {
                let (send, handle) = member(index + 1);
                set.insert_member(handle);
                if ready_error && index == 63 {
                    send.send(&cx, Ok(Err("nonwinning application error"))).unwrap();
                } else {
                    senders.push(send);
                }
            }
            let ready = Arc::clone(&set.ready);
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut task = Context::from_waker(&waker);
            let mut joining = Box::pin(set.join_quorum(&cx, 1));
            for (candidates, notifications) in [(66, 1), (2, 2), (0, 2), (0, 2)] {
                assert!(joining.as_mut().poll(&mut task).is_pending());
                assert_eq!(ready.candidates.lock().len(), candidates);
                assert_eq!(wakes.0.load(Ordering::SeqCst), notifications);
            }
            drop(joining);
            assert!(ready.waiter.lock().is_none());
            drop(senders);
        }
    }

    #[test]
    fn backward_wakes_do_not_starve_the_unexamined_suffix() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(RegionId::new_for_test(2, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let mut senders = Vec::new();
        for index in 0..130 {
            let (send, handle) = member(index + 1);
            set.insert_member(handle);
            senders.push(Some(send));
        }
        let ready = Arc::clone(&set.ready);
        let mut remaining = 64;
        let mut waiting = Box::pin(set.next_outcome_bounded(&mut remaining));
        let mut task = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        senders[129].take().unwrap().send(&cx, Ok(Err("suffix"))).unwrap();
        for pass in 0..2 {
            for index in 0..64 {
                Waker::from(Arc::new(MemberWake { index, ready: Arc::clone(&ready) })).wake();
            }
            let outcome = waiting.as_mut().poll(&mut task);
            if pass == 0 {
                assert!(outcome.is_pending());
            } else {
                assert!(matches!(outcome, Poll::Ready(Some(Outcome::Err("suffix")))));
            }
        }
        drop(waiting);
        assert_eq!(set.len(), 129);
        for send in senders.into_iter().flatten() {
            send.send(&cx, Ok(Ok(7))).unwrap();
        }
        let outcomes = futures_lite::future::block_on(set.join_all(&cx));
        assert_eq!(outcomes.len(), 129);
        assert!(outcomes.iter().all(|outcome| matches!(outcome, Outcome::Ok(7))));
    }

    #[test]
    fn dropped_bounded_wait_preserves_members_and_retires_only_its_subscription() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(RegionId::new_for_test(3, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let (first, handle) = member(1);
        set.insert_member(handle);
        let (second, handle) = member(2);
        set.insert_member(handle);
        let ready = Arc::clone(&set.ready);
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        let mut remaining = 64;
        let mut waiting = Box::pin(set.next_outcome_bounded(&mut remaining));
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert!(ready.waiter.lock().is_some());
        drop(waiting);
        assert!(ready.waiter.lock().is_none());
        second.send(&cx, Ok(Ok(2))).unwrap();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        assert!(matches!(set.try_join_next(), Some(Outcome::Ok(2))));
        first.send(&cx, Ok(Ok(1))).unwrap();
        assert!(matches!(set.try_join_next(), Some(Outcome::Ok(1))));
        assert!(set.is_empty());
    }

    #[test]
    fn selection_drain_yields_between_ready_spawn_order_batches() {
        let cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(RegionId::new_for_test(4, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        for index in 0..130 {
            let (send, handle) = member(index + 1);
            set.insert_member(handle);
            send.send(&cx, Ok(Ok(u16::try_from(index).unwrap()))).unwrap();
        }
        let ready = Arc::clone(&set.ready);
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        let mut draining = Box::pin(set.cancel_remaining_for_selection(CancelReason::race_loser()));
        for (left, notifications) in [(66, 1), (2, 2)] {
            assert!(draining.as_mut().poll(&mut task).is_pending());
            assert_eq!(ready.candidates.lock().len(), left);
            assert_eq!(wakes.0.load(Ordering::SeqCst), notifications);
        }
        let Poll::Ready(outcomes) = draining.as_mut().poll(&mut task) else {
            panic!("all 130 members must retire in three batches");
        };
        let values = outcomes.into_iter().map(|outcome| outcome.expect("published value"));
        assert_eq!(values.collect::<Vec<_>>(), (0_u16..130).collect::<Vec<_>>());
        assert!(ready.candidates.lock().is_empty());
    }

    #[test]
    fn selection_drain_cancels_suffix_without_rewriting_a_published_cancellation() {
        let cx = Cx::for_testing();
        let published_cx = Cx::for_testing();
        let unfinished_cx = Cx::for_testing();
        let scope = Scope::<FailFast>::new(RegionId::new_for_test(5, 0), Budget::INFINITE);
        let mut set = JoinSet::<u16, &'static str, _>::new(&scope);
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        let (send, receive) = oneshot::channel();
        set.insert_member(TaskHandle::with_retirement_barrier_for_test(
            TaskId::new_for_test(1, 0), receive, Arc::downgrade(&published_cx.inner), Arc::clone(&barrier),
        ));
        send.send(&cx, Err(JoinError::Cancelled(CancelReason::user("published reason")))).unwrap();
        let (send, receive) = oneshot::channel();
        set.insert_member(TaskHandle::new(
            TaskId::new_for_test(2, 0), receive, Arc::downgrade(&unfinished_cx.inner),
        ));
        let mut draining = Box::pin(set.cancel_remaining_for_selection(CancelReason::fail_fast()));
        let mut task = Context::from_waker(Waker::noop());
        assert!(draining.as_mut().poll(&mut task).is_pending());
        assert!(!published_cx.is_cancel_requested());
        assert!(unfinished_cx.is_cancel_requested(), "cancel the suffix before waiting on the head");
        let forwarded = unfinished_cx.cancel_reason().unwrap();
        assert_eq!(forwarded.kind, CancelReason::fail_fast().kind);
        send.send(&cx, Err(JoinError::Cancelled(forwarded))).unwrap();
        barrier.open_and_wake();
        let Poll::Ready(outcomes) = draining.as_mut().poll(&mut task) else {
            panic!("retirement opens the final publication barrier");
        };
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(&outcomes[0], Outcome::Cancelled(reason)
            if reason.kind == CancelKind::User && reason.message.as_deref() == Some("published reason")));
        assert!(matches!(&outcomes[1], Outcome::Cancelled(reason)
            if reason.kind == CancelReason::fail_fast().kind));
        assert!(!published_cx.is_cancel_requested());
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use super::*;
        use crate::combinator::QuorumError;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder, yield_now};
        use std::pin::pin;
        use std::sync::mpsc;
        use std::time::Duration;

        fn run<F, Fut>(test: F)
        where
            F: Fn(Cx) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = ()> + Send + 'static,
        {
            let (send, receive) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let test = Arc::new(test);
                    for workers in [1, 2] {
                        let builder = if workers == 1 {
                            RuntimeBuilder::current_thread()
                        } else {
                            RuntimeBuilder::new().worker_threads(workers)
                        };
                        let runtime = builder.build().unwrap();
                        let test = Arc::clone(&test);
                        runtime.block_on(runtime.handle().spawn(async move {
                            test(Cx::current().expect("native parent context")).await;
                        }));
                        let report = runtime.shutdown_drained(Duration::from_secs(5));
                        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                        assert_eq!(report.live_tasks, 0);
                        assert_eq!(report.pending_spawns, 0);
                        assert_eq!(report.pending_obligations, 0);
                    }
                }));
                let _ = send.send(result);
            });
            let result = receive
                .recv_timeout(Duration::from_secs(45))
                .expect("native bounded quorum exceeded watchdog");
            worker.join().unwrap();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }

        async fn park(child: &Cx, started: oneshot::Sender<Cx>) -> CancelReason {
            let mut started = Some(started);
            let mut cancellation = pin!(child.cancelled());
            poll_fn(|task| match cancellation.as_mut().poll(task) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending => {
                    if let Some(started) = started.take() {
                        // The native cancellation registration exists before
                        // the parent receives this parked-state witness.
                        started.send_blocking(child.clone()).unwrap();
                    }
                    Poll::Pending
                }
            })
            .await;
            assert!(child.checkpoint().is_err());
            child.cancel_reason().expect("acknowledged cancellation")
        }

        #[test]
        fn native_quorum_bounds_parked_scan_then_collects_a_woken_suffix() {
            run(|cx| async move {
                let mut set = JoinSet::<u16, &'static str, _>::in_cx(&cx);
                let cleaned = Arc::new(AtomicUsize::new(0));
                for _ in 0..129 {
                    let (started, mut witness) = oneshot::channel();
                    let cleaned = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        let reason = park(&child, started).await;
                        assert_eq!(reason.kind, CancelKind::RaceLost);
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        Ok(0)
                    }).unwrap();
                    witness.recv(&cx).await.unwrap();
                }
                let (release, mut gate) = oneshot::channel();
                let (started, mut witness) = oneshot::channel();
                set.spawn(&cx, move |child| async move {
                    let mut started = Some(started);
                    let mut waiting = pin!(gate.recv(&child));
                    poll_fn(|task| {
                        let result = waiting.as_mut().poll(task);
                        if result.is_pending() && let Some(started) = started.take() {
                            started.send_blocking(()).unwrap();
                        }
                        result
                    }).await.unwrap();
                    Ok(42)
                }).unwrap();
                witness.recv(&cx).await.unwrap();
                let ready = Arc::clone(&set.ready);
                assert_eq!(ready.candidates.lock().len(), 130);
                let mut joining = Box::pin(set.join_first_ok(&cx));
                poll_fn(|task| {
                    assert!(joining.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                let unexamined = ready.candidates.lock().len();
                assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                release.send_blocking(()).unwrap();
                assert_eq!(joining.await.unwrap(), 42);
                assert_eq!(cleaned.load(Ordering::SeqCst), 129);
                // Release/drain first so the old-code control fails here,
                // not because a test assertion stranded the parked suffix.
                assert_eq!(unexamined, 66, "one native poll must examine only 64 candidates");
                assert!(!cx.is_cancel_requested());
            });
        }

        #[test]
        fn native_owner_abort_reaches_unscanned_members_and_waits_for_cleanup() {
            run(|cx| async move {
                let mut set = JoinSet::<u16, &'static str, _>::in_cx(&cx);
                let cleaned = Arc::new(AtomicUsize::new(0));
                let mut releases = Vec::new();
                let mut cleanup_witnesses = Vec::new();
                for _ in 0..130 {
                    let (started, mut witness) = oneshot::channel();
                    let (release, mut cleanup) = oneshot::channel::<()>();
                    let (cleanup_ready, cleanup_witness) = oneshot::channel();
                    let cleaned = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        let reason = park(&child, started).await;
                        let mut cleanup_ready = Some(cleanup_ready);
                        poll_fn(|task| {
                            let result = cleanup.poll_recv_uninterruptible(task);
                            if result.is_pending() && let Some(ready) = cleanup_ready.take() {
                                ready.send_blocking(reason.clone()).unwrap();
                            }
                            result
                        }).await.unwrap();
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        Ok(0)
                    }).unwrap();
                    witness.recv(&cx).await.unwrap();
                    releases.push(release);
                    cleanup_witnesses.push(cleanup_witness);
                }
                let ready = Arc::clone(&set.ready);
                let (first_poll, mut witness) = oneshot::channel();
                let (resume, mut pause) = oneshot::channel::<()>();
                let mut owner = cx.spawn(move |owner| async move {
                    let mut joining = Box::pin(set.join_quorum(&owner, 1));
                    poll_fn(|task| {
                        assert!(joining.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    first_poll.send_blocking(()).unwrap();
                    // Keep the scan frozen while the parent injects owner
                    // cancellation. This is a real registered wait, not sleep.
                    poll_fn(|task| pause.poll_recv_uninterruptible(task)).await.unwrap();
                    joining.await
                }).unwrap();
                witness.recv(&cx).await.unwrap();
                let unexamined_at_abort = ready.candidates.lock().len();
                owner.abort_with_reason(CancelReason::shutdown());
                resume.send_blocking(()).unwrap();
                for mut witness in cleanup_witnesses {
                    let reason = witness.recv(&cx).await.unwrap();
                    assert_eq!(reason.kind, CancelKind::Shutdown);
                }
                assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                assert!(matches!(owner.try_join(), Ok(None)), "all cleanup gates are still closed");
                for release in releases {
                    release.send_blocking(()).unwrap();
                }
                assert!(matches!(owner.join(&cx).await.unwrap(),
                    Err(QuorumError::Cancelled(reason)) if reason.kind == CancelKind::Shutdown));
                assert_eq!(cleaned.load(Ordering::SeqCst), 130);
                assert_eq!(unexamined_at_abort, 66);
                assert!(!cx.is_cancel_requested());
            });
        }

        #[test]
        fn native_invalid_quorum_yields_drain_without_cancelling_retired_members() {
            run(|cx| async move {
                let mut set = JoinSet::<u16, &'static str, _>::in_cx(&cx);
                let mut children = Vec::new();
                for index in 0..130_u16 {
                    let (published, mut witness) = oneshot::channel();
                    set.spawn(&cx, move |child| async move {
                        published.send_blocking(child.clone()).unwrap();
                        Ok(index)
                    }).unwrap();
                    children.push(witness.recv(&cx).await.unwrap());
                }
                // A factory sending its context is not a completion receipt.
                // Wait for the actual native handles to witness retirement.
                while set.members.values().any(|member| !member.handle.is_finished()) {
                    yield_now().await;
                }
                assert!(children.iter().all(|child| !child.is_cancel_requested()));
                let ready = Arc::clone(&set.ready);
                let mut joining = Box::pin(set.join_quorum(&cx, 0));
                let first = poll_fn(|task| Poll::Ready(joining.as_mut().poll(task))).await;
                let yielded = first.is_pending();
                let remaining = ready.candidates.lock().len();
                let result = match first {
                    Poll::Ready(result) => result,
                    Poll::Pending => joining.await,
                };
                assert!(matches!(result, Err(QuorumError::InvalidQuorum { required: 0, total: 130 })));
                assert!(yielded, "ready cleanup must yield after 64 retirements");
                assert_eq!(remaining, 66);
                assert!(children.iter().all(|child| !child.is_cancel_requested()),
                    "invalid parameters must not rewrite already-published native task state");
                assert!(!cx.is_cancel_requested());
            });
        }
    }
