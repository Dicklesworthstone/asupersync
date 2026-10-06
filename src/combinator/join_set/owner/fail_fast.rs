//! Fail-fast collection with failure attribution retained through sibling drain.

use super::super::{JoinSet, MemberWake, join_to_outcome};
use crate::cx::Cx;
use crate::types::{CancelReason, Outcome, Policy};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const CANDIDATES_PER_POLL: usize = 64;

enum Failure {
    Member(u64),
    Owner(CancelReason),
}

// Retain *all* results until every member retires. Discarding a successful
// value (or a secondary error) during drain could run a panicking user Drop
// before the remaining children have finished their asynchronous cleanup.
struct Collected<T, E> {
    outcomes: BTreeMap<u64, Outcome<T, E>>,
    failure: Option<Failure>,
    first_panic: Option<u64>,
}

impl<T, E> Collected<T, E> {
    fn new() -> Self {
        Self {
            outcomes: BTreeMap::new(),
            failure: None,
            first_panic: None,
        }
    }

    /// Return a cancellation reason only on the first non-success transition.
    fn record(&mut self, index: u64, outcome: Outcome<T, E>) -> Option<CancelReason> {
        let cancel = if self.failure.is_none() {
            match &outcome {
                Outcome::Ok(_) => None,
                Outcome::Err(_) | Outcome::Panicked(_) => Some(CancelReason::fail_fast()),
                Outcome::Cancelled(reason) => Some(reason.clone()),
            }
        } else {
            None
        };
        if cancel.is_some() {
            self.failure = Some(Failure::Member(index));
        }
        if matches!(&outcome, Outcome::Panicked(_)) && self.first_panic.is_none() {
            self.first_panic = Some(index);
        }
        let previous = self.outcomes.insert(index, outcome);
        debug_assert!(previous.is_none(), "member collected twice");
        cancel
    }

    fn finish(mut self) -> Outcome<Vec<T>, E> {
        let failure = self.first_panic.map(Failure::Member).or(self.failure);
        match failure {
            Some(Failure::Owner(reason)) => Outcome::Cancelled(reason),
            Some(Failure::Member(index)) => {
                match self.outcomes.remove(&index).expect("selected outcome retained") {
                    Outcome::Err(error) => Outcome::Err(error),
                    Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => Outcome::Panicked(payload),
                    Outcome::Ok(_) => unreachable!("selected failure cannot be a success"),
                }
            }
            None => Outcome::Ok(
                self.outcomes
                    .into_values()
                    .map(|outcome| match outcome {
                        Outcome::Ok(value) => value,
                        _ => unreachable!("non-success must select a failure"),
                    })
                    .collect(),
            ),
        }
    }
}

impl<T, E, P> JoinSet<'_, T, E, P>
where
    T: Send + 'static,
    E: Send + 'static,
    P: Policy,
{
    /// Join the remaining members, cancelling and draining siblings on failure.
    ///
    /// Unlike [`Self::join_all`], this observes completion candidates rather
    /// than waiting for the first input: a parked early member cannot hide a
    /// later member's error. Successful values are returned in spawn order,
    /// excluding members already collected before this call. Empty input is
    /// `Outcome::Ok(Vec::new())`, even for an already-cancelled caller.
    ///
    /// The first observed member error/cancellation selects the result and
    /// requests cancellation of every unfinished sibling before drain. Sibling
    /// cancellations caused by fail-fast cleanup do not replace that initiating
    /// error. A member panic observed at any point takes precedence; among
    /// several panics, the first observed panic is retained. Simultaneously
    /// examined candidates use their spawn indices as a deterministic tie-break.
    ///
    /// If the caller's cancellation is observed while a member is still running
    /// and before a member failure is selected, its reason selects
    /// `Outcome::Cancelled` instead. Already-published members are still joined
    /// to retirement, but do not make a completed group become cancelled merely
    /// because collection spans several polling quanta. Observation
    /// is mask-agnostic, while checkpoint acknowledgement respects masking.
    /// A later caller cancellation does not overwrite a selected failure.
    /// All members still retire before any result is returned. Successful
    /// values and secondary errors are retained until then, so their destructors
    /// cannot interrupt the asynchronous drain. No result needs to be `Clone`.
    ///
    /// Uses the set's existing ready index and persistent per-member wakers.
    /// At most 64 candidates are examined per poll, including pending ones;
    /// additional candidates schedule another poll instead of monopolizing a
    /// worker. The scan cursor survives yielded polls so repeatedly woken early
    /// members cannot starve a later failure. A fully parked set registers
    /// cancellation without self-spinning.
    ///
    /// Dropping this consuming future, including before its first poll,
    /// requests cancellation through the set's existing Drop implementation.
    /// The original regions remain the drain backstop. This does not create a
    /// region, detach tasks, forcibly preempt a non-cooperative member, or change
    /// the existing observation-only join APIs.
    pub async fn try_join_all<Caps>(mut self, cx: &Cx<Caps>) -> Outcome<Vec<T>, E> {
        let mut collected = Collected::new();
        let mut cancelled = pin!(cx.cancelled());
        let mut owner_observed = false;
        let mut scan_from = 0;
        poll_fn(|task| {
            if self.members.is_empty() {
                return Poll::Ready(());
            }

            // Clone and retire caller wakers outside the waiter mutex: these
            // are user callbacks, including the last-reference destructor.
            let incoming = task.waker().clone();
            let previous = self.ready.waiter.lock().replace(incoming);
            drop(previous);

            let mut from = Some(scan_from);
            for _ in 0..CANDIDATES_PER_POLL {
                let Some(index) = from.and_then(|start| self.ready.next_candidate(start)) else {
                    break;
                };
                from = index.checked_add(1);
                self.ready.candidates.lock().remove(&index);
                let ready = Arc::clone(&self.ready);
                let Some(member) = self.members.get_mut(&index) else {
                    // A late wake from an already-collected member is harmless.
                    continue;
                };
                let waker = member.waker.get_or_insert_with(|| {
                    Waker::from(Arc::new(MemberWake { index, ready }))
                });
                if let Poll::Ready(joined) = member.handle.poll_join(&mut Context::from_waker(waker)) {
                    let outcome = join_to_outcome(joined);
                    self.take_member(index, &outcome);
                    if let Some(reason) = collected.record(index, outcome) {
                        self.cancel_unfinished_for_owner(&reason);
                    }
                }
            }

            if self.members.is_empty() {
                return Poll::Ready(());
            }
            let mut transition_wake = false;
            if !owner_observed && collected.failure.is_none() && cancelled.as_mut().poll(task).is_ready() {
                owner_observed = true;
                if self.members.values().any(|member| !member.handle.terminal_published()) {
                    let reason = cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("fail-fast join owner cancelled"));
                    collected.failure = Some(Failure::Owner(reason.clone()));
                    let _ = cx.checkpoint();
                    self.cancel_unfinished_for_owner(&reason);
                    transition_wake = true;
                }
            }
            let more_forward = from.is_some_and(|start| self.ready.next_candidate(start).is_some());
            scan_from = if more_forward {
                from.expect("a forward candidate has a scan cursor")
            } else {
                0
            };
            // Backward arrivals are revisited only after the current sweep.
            // Their wakes may have happened during this poll; retain explicit
            // runnable work at the quantum boundary rather than losing it.
            let runnable = !self.ready.candidates.lock().is_empty();
            if transition_wake || runnable {
                task.waker().wake_by_ref();
            }
            Poll::Pending
        }).await;
        collected.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::oneshot;
    use crate::runtime::{JoinError, TaskHandle};
    use crate::types::{Budget, CancelKind, RegionId, TaskId};
    use crate::types::policy::FailFast;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    fn manual_member<T>(slot: u32) -> (
        oneshot::Sender<Result<Result<T, &'static str>, JoinError>>,
        TaskHandle<Result<T, &'static str>>,
    ) {
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
    fn reverse_completion_returns_spawn_order_and_does_not_lose_member_wakes() {
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(RegionId::new_for_test(1, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let mut senders = Vec::new();
        for index in 0..4 {
            let (send, handle) = manual_member::<u32>(index + 1);
            set.insert_member(handle);
            senders.push(Some(send));
        }
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut task = Context::from_waker(&waker);
        let mut joining = Box::pin(set.try_join_all(&cx));
        assert!(joining.as_mut().poll(&mut task).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        for index in [3, 2, 1, 0] {
            let before = count.0.load(Ordering::SeqCst);
            senders[index].take().unwrap().send(&cx, Ok(Ok(index as u32))).unwrap();
            assert!(count.0.load(Ordering::SeqCst) > before, "published member must wake collector");
            match joining.as_mut().poll(&mut task) {
                Poll::Pending => assert_ne!(index, 0),
                Poll::Ready(Outcome::Ok(values)) => {
                    assert_eq!(index, 0);
                    assert_eq!(values, [0, 1, 2, 3]);
                }
                other @ Poll::Ready(_) => panic!("unexpected collection result: {other:?}"),
            }
        }
    }

    #[test]
    fn candidate_registration_is_bounded_and_parked_collector_does_not_spin() {
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(RegionId::new_for_test(2, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let mut senders = Vec::new();
        for slot in 0..130 {
            let (send, handle) = manual_member::<()>(slot + 1);
            set.insert_member(handle);
            senders.push(send);
        }
        let ready = Arc::clone(&set.ready);
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut task = Context::from_waker(&waker);
        let mut joining = Box::pin(set.try_join_all(&cx));
        for (left, wakes) in [(66, 1), (2, 2), (0, 2), (0, 2)] {
            assert!(joining.as_mut().poll(&mut task).is_pending());
            assert_eq!(ready.candidates.lock().len(), left);
            assert_eq!(count.0.load(Ordering::SeqCst), wakes);
        }
        drop(joining);
        drop(senders);
    }

    #[test]
    fn repeatedly_woken_prefix_cannot_starve_a_later_error() {
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(RegionId::new_for_test(5, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let mut senders = Vec::new();
        for slot in 0..130 {
            let (send, handle) = manual_member::<()>(slot + 1);
            set.insert_member(handle);
            senders.push(Some(send));
        }
        let ready = Arc::clone(&set.ready);
        let mut joining = Box::pin(set.try_join_all(&cx));
        let mut task = Context::from_waker(Waker::noop());
        assert!(joining.as_mut().poll(&mut task).is_pending());
        senders[129].take().unwrap().send(&cx, Ok(Err("late-index failure"))).unwrap();
        for _ in 0..2 {
            for index in 0..64 {
                // Exercise the production wake path, not a parallel model of
                // candidate registration. Spurious wakeups are permitted.
                Waker::from(Arc::new(MemberWake { index, ready: Arc::clone(&ready) })).wake();
            }
            assert!(joining.as_mut().poll(&mut task).is_pending());
        }
        assert!(!ready.candidates.lock().contains(&129), "the high-index error must have been collected");
        for send in senders.into_iter().flatten() {
            send.send(&cx, Ok(Ok(()))).unwrap();
        }
        assert!(matches!(futures_lite::future::block_on(joining), Outcome::Err("late-index failure")));
    }

    #[test]
    fn empty_cancelled_set_succeeds_without_inventing_work() {
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, Some("empty group"));
        let set = JoinSet::<u8, (), _>::in_cx(&cx);
        let outcome = futures_lite::future::block_on(set.try_join_all(&cx));
        assert!(matches!(outcome, Outcome::Ok(values) if values.is_empty()));
    }

    #[test]
    fn already_published_group_is_not_cancelled_by_the_poll_budget_boundary() {
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(RegionId::new_for_test(3, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        for index in 0..130 {
            let (send, handle) = manual_member::<u32>(index + 1);
            set.insert_member(handle);
            send.send(&cx, Ok(Ok(index))).unwrap();
        }
        cx.cancel_with(CancelKind::User, Some("all members already published"));
        let outcome = futures_lite::future::block_on(set.try_join_all(&cx));
        match outcome {
            Outcome::Ok(values) => assert_eq!(values, (0..130).collect::<Vec<_>>()),
            other => panic!("polling quanta must not change completed outcomes: {other:?}"),
        }
    }

    #[test]
    fn transfer_from_a_dropped_incremental_wait_preserves_persistent_member_wakes() {
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(RegionId::new_for_test(4, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let (first, handle) = manual_member::<u8>(1);
        set.insert_member(handle);
        let (second, handle) = manual_member::<u8>(2);
        set.insert_member(handle);
        {
            let mut incremental = Box::pin(set.join_next(&cx));
            assert!(incremental.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert!(set.ready.candidates.lock().is_empty());
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut task = Context::from_waker(&waker);
        let mut joining = Box::pin(set.try_join_all(&cx));
        assert!(joining.as_mut().poll(&mut task).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        second.send(&cx, Ok(Err("after incremental wait"))).unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(joining.as_mut().poll(&mut task).is_pending());
        first.send(&cx, Ok(Ok(3))).unwrap();
        assert!(matches!(joining.as_mut().poll(&mut task),
            Poll::Ready(Outcome::Err("after incremental wait"))));
    }

    #[test]
    fn published_result_is_not_cancelled_and_retirement_still_gates_failure_return() {
        let cx = Cx::for_testing();
        let finished_cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(RegionId::new_for_test(6, 0), Budget::INFINITE);
        let mut set = JoinSet::new(&scope);
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        let (send, receive) = oneshot::channel();
        set.insert_member(TaskHandle::with_retirement_barrier_for_test(
            TaskId::new_for_test(1, 0),
            receive,
            Arc::downgrade(&finished_cx.inner),
            Arc::clone(&barrier),
        ));
        send.send(&cx, Ok(Ok(7_u8))).unwrap();
        assert!(!set.members[&0].handle.is_finished());
        let (send, handle) = manual_member::<u8>(2);
        set.insert_member(handle);
        send.send(&cx, Ok(Err("other member failed"))).unwrap();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut task = Context::from_waker(&waker);
        let mut joining = Box::pin(set.try_join_all(&cx));
        assert!(joining.as_mut().poll(&mut task).is_pending(), "retirement is still blocked");
        assert!(!finished_cx.is_cancel_requested(), "published success must not be strengthened");
        let before = count.0.load(Ordering::SeqCst);
        barrier.open_and_wake();
        assert!(count.0.load(Ordering::SeqCst) > before, "retirement must wake the collector");
        assert!(matches!(joining.as_mut().poll(&mut task),
            Poll::Ready(Outcome::Err("other member failed"))));
        assert!(!finished_cx.is_cancel_requested());
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use super::*;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder, yield_now};
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
                            test(Cx::current().expect("runtime task context")).await;
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
            let result = receive.recv_timeout(Duration::from_secs(45))
                .expect("fail-fast group must drain every child");
            worker.join().unwrap();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }

        async fn park(cx: &Cx, started: oneshot::Sender<Cx>) {
            let mut started = Some(started);
            let mut cancelled = pin!(cx.cancelled());
            poll_fn(|task| match cancelled.as_mut().poll(task) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending => {
                    if let Some(started) = started.take() {
                        started.send_blocking(cx.clone()).unwrap();
                    }
                    Poll::Pending
                }
            }).await;
            assert!(cx.checkpoint().is_err());
        }

        #[test]
        fn later_error_is_not_hidden_by_first_parked_child_and_waits_for_cleanup() {
            run(|cx| async move {
                let owner = Cx::detached_cancel_context();
                let mut set = JoinSet::<usize, &'static str, _>::in_cx(&cx);
                let (started, mut parked) = oneshot::channel();
                let (release, mut cleanup) = oneshot::channel::<()>();
                let drain_cx = cx.clone();
                set.spawn(&cx, move |child| async move {
                    park(&child, started).await;
                    cleanup.recv(&drain_cx).await.unwrap();
                    Ok(1)
                }).unwrap();
                let first = parked.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("later member failed") }).unwrap();
                let mut joining = Box::pin(set.try_join_all(&owner));
                poll_fn(|task| {
                    assert!(joining.as_mut().poll(task).is_pending(), "cleanup gate is still closed");
                    if first.is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                assert_eq!(first.cancel_reason().unwrap().kind, CancelReason::fail_fast().kind);
                assert!(!cx.is_cancel_requested());
                // The initiating application error is already selected. A
                // later owner request must not replace it during cleanup.
                owner.cancel_with(CancelKind::Shutdown, Some("late owner shutdown"));
                release.send_blocking(()).unwrap();
                assert!(matches!(joining.await, Outcome::Err("later member failed")));
            });
        }

        #[test]
        fn owner_race_loss_is_not_reported_as_retryable_cleanup_error() {
            run(|cx| async move {
                let owner = Cx::detached_cancel_context();
                let mut set = JoinSet::<(), &'static str, _>::in_cx(&cx);
                let cleaned = Arc::new(AtomicUsize::new(0));
                for _ in 0..3 {
                    let (started, mut parked) = oneshot::channel();
                    let cleaned = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        park(&child, started).await;
                        yield_now().await;
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        Err("cleanup application error")
                    }).unwrap();
                    parked.recv(&cx).await.unwrap();
                }
                owner.cancel_with(CancelKind::RaceLost, Some("outer race lost"));
                let outcome = set.try_join_all(&owner).await;
                assert!(matches!(outcome, Outcome::Cancelled(reason) if reason.kind == CancelKind::RaceLost));
                assert_eq!(cleaned.load(Ordering::SeqCst), 3);
                assert!(!cx.is_cancel_requested());
            });
        }

        #[test]
        fn independent_child_cancellation_propagates_its_reason_to_siblings() {
            run(|cx| async move {
                let mut set = JoinSet::<(), &'static str, _>::in_cx(&cx);
                let mut children = Vec::new();
                let cleaned = Arc::new(AtomicUsize::new(0));
                for _ in 0..3 {
                    let (started, mut parked) = oneshot::channel();
                    let cleaned = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        park(&child, started).await;
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }).unwrap();
                    children.push(parked.recv(&cx).await.unwrap());
                }
                children[1].cancel_with(CancelKind::Shutdown, Some("member independently stopped"));
                assert!(matches!(set.try_join_all(&cx).await,
                    Outcome::Cancelled(reason) if reason.kind == CancelKind::Shutdown));
                assert!(children.iter().all(|child|
                    child.cancel_reason().unwrap().kind == CancelKind::Shutdown));
                assert_eq!(cleaned.load(Ordering::SeqCst), 3);
                assert!(!cx.is_cancel_requested());
            });
        }

        #[test]
        fn local_members_stay_on_their_owner_thread_through_fail_fast_cleanup() {
            run(|cx| async move {
                let mut set = JoinSet::<usize, &'static str, _>::in_cx(&cx);
                let cleaned = Arc::new(AtomicUsize::new(0));
                for index in 0..2 {
                    let (started, mut parked) = oneshot::channel();
                    let marker = std::rc::Rc::new(index);
                    let cleaned = Arc::clone(&cleaned);
                    set.spawn_local(&cx, move |child| async move {
                        let thread = std::thread::current().id();
                        park(&child, started).await;
                        yield_now().await;
                        assert_eq!(std::thread::current().id(), thread);
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        Ok(*marker)
                    }).unwrap();
                    parked.recv(&cx).await.unwrap();
                }
                set.spawn(&cx, |_| async { Err("stop local group") }).unwrap();
                assert!(matches!(set.try_join_all(&cx).await, Outcome::Err("stop local group")));
                assert_eq!(cleaned.load(Ordering::SeqCst), 2);
            });
        }

        #[test]
        fn panic_during_error_drain_takes_precedence_without_skipping_siblings() {
            run(|cx| async move {
                let mut set = JoinSet::<(), &'static str, _>::in_cx(&cx);
                let (started, mut parked) = oneshot::channel();
                set.spawn(&cx, move |child| async move {
                    park(&child, started).await;
                    panic!("fail-fast cleanup panic");
                }).unwrap();
                parked.recv(&cx).await.unwrap();
                let (started, mut parked) = oneshot::channel();
                let cleaned = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&cleaned);
                set.spawn(&cx, move |child| async move {
                    park(&child, started).await;
                    yield_now().await;
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }).unwrap();
                parked.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("initiating error") }).unwrap();
                let outcome = set.try_join_all(&cx).await;
                assert!(matches!(outcome, Outcome::Panicked(payload)
                    if payload.message().contains("fail-fast cleanup panic")));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }

        struct ValueDrop(Arc<AtomicUsize>);

        impl Drop for ValueDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn completed_values_are_not_destroyed_until_remaining_cleanup_retires() {
            run(|cx| async move {
                let drops = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&drops);
                let mut set = JoinSet::<ValueDrop, &'static str, _>::in_cx(&cx);
                set.spawn(&cx, move |_| async move { Ok(ValueDrop(observed)) }).unwrap();
                while !set.members[&0].handle.is_finished() {
                    yield_now().await;
                }
                let (started, mut parked) = oneshot::channel();
                let (release, mut cleanup) = oneshot::channel::<()>();
                let drain_cx = cx.clone();
                set.spawn(&cx, move |child| async move {
                    park(&child, started).await;
                    cleanup.recv(&drain_cx).await.unwrap();
                    Err("secondary error")
                }).unwrap();
                let child = parked.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("initiating error") }).unwrap();
                let mut joining = Box::pin(set.try_join_all(&cx));
                poll_fn(|task| {
                    assert!(joining.as_mut().poll(task).is_pending());
                    if child.is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                assert_eq!(drops.load(Ordering::SeqCst), 0, "values must remain owned throughout drain");
                release.send_blocking(()).unwrap();
                assert!(matches!(joining.await, Outcome::Err("initiating error")));
                assert_eq!(drops.load(Ordering::SeqCst), 1);
            });
        }

        #[test]
        fn dropping_unpolled_or_partially_collected_future_cancels_the_entire_remainder() {
            run(|cx| async move {
                for poll_first in [false, true] {
                    let mut set = JoinSet::<usize, (), _>::in_cx(&cx);
                    let mut children = Vec::new();
                    for index in 0..3 {
                        let (started, mut parked) = oneshot::channel();
                        set.spawn(&cx, move |child| async move {
                            park(&child, started).await;
                            Ok(index)
                        }).unwrap();
                        children.push(parked.recv(&cx).await.unwrap());
                    }
                    let mut joining = Box::pin(set.try_join_all(&cx));
                    if poll_first {
                        poll_fn(|task| {
                            assert!(joining.as_mut().poll(task).is_pending());
                            Poll::Ready(())
                        }).await;
                    }
                    drop(joining);
                    assert!(children.iter().all(Cx::is_cancel_requested));
                    assert!(!cx.is_cancel_requested());
                }
            });
        }
    }
}
