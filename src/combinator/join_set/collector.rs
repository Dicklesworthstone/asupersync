//! Lifetime of the task waiting for a member, separate from member readiness.

use super::{JoinSet, Outcome, Policy, ReadyMembers, join_to_outcome};
use crate::types::CancelReason;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Poll, Waker};

impl<T, E, P> JoinSet<'_, T, E, P>
where
    T: Send + 'static,
    E: Send + 'static,
    P: Policy,
{
    pub(in crate::combinator) const SELECTION_CANDIDATES_PER_POLL: usize = 64;

    /// A selection scan shares its quantum across consecutive ready outcomes.
    /// Pending candidates count too. Keep the cursor while this wait is pending
    /// so a repeatedly woken prefix cannot hide an unexamined suffix forever.
    pub(in crate::combinator) async fn next_outcome_bounded(
        &mut self,
        remaining: &mut usize,
    ) -> Option<Outcome<T, E>> {
        let mut collector = CollectorWait::new(Arc::clone(&self.ready));
        let mut scan_from = 0;
        poll_fn(|task| {
            if self.members.is_empty() {
                return Poll::Ready(None);
            }
            collector.refresh(task.waker());
            let mut from = Some(scan_from);
            while *remaining > 0 {
                let Some(index) = from.and_then(|start| self.ready.next_candidate(start)) else {
                    break;
                };
                *remaining -= 1;
                from = index.checked_add(1);
                if let Some(outcome) = self.poll_candidate(index) {
                    return Poll::Ready(Some(outcome));
                }
            }
            let more_forward = from.is_some_and(|start| self.ready.next_candidate(start).is_some());
            scan_from = if more_forward {
                from.expect("forward candidate has a cursor")
            } else {
                0
            };
            // Refresh happened before the scan. A concurrent member wake
            // therefore either leaves an explicit candidate or wakes this wait.
            // Backward arrivals are revisited after the current forward sweep.
            let runnable = !self.ready.candidates.lock().is_empty();
            *remaining = Self::SELECTION_CANDIDATES_PER_POLL;
            if runnable {
                task.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }

    /// Cancel every unfinished member before awaiting any retirement, then
    /// collect in bounded spawn-order batches. Published outcomes are immutable
    /// even while their retirement barrier is closed. Legacy explicit-abort
    /// APIs retain their separate reason-strengthening behavior.
    pub(in crate::combinator) async fn cancel_remaining_for_selection(
        self,
        reason: CancelReason,
    ) -> Vec<Outcome<T, E>> {
        let mut outcomes = Vec::with_capacity(self.members.len());
        // On drop or unwind, request the remaining cancellations before user
        // values in the collected prefix are destroyed (v8rp1h L6).
        let mut members = self;
        let mut first_panic = None;
        for member in members.members.values() {
            if !member.handle.terminal_published()
                && let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    member.handle.abort_with_reason(reason.clone());
                }))
                && first_panic.is_none()
            {
                first_panic = Some(payload);
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
        poll_fn(|task| {
            for _ in 0..Self::SELECTION_CANDIDATES_PER_POLL {
                let Some((&index, _)) = members.members.first_key_value() else {
                    return Poll::Ready(std::mem::take(&mut outcomes));
                };
                let joined = members
                    .members
                    .get_mut(&index)
                    .expect("first member remains owned")
                    .handle
                    .poll_join(task);
                let Poll::Ready(joined) = joined else {
                    return Poll::Pending;
                };
                let outcome = join_to_outcome(joined);
                members.take_member(index, &outcome);
                outcomes.push(outcome);
            }
            if members.members.is_empty() {
                Poll::Ready(std::mem::take(&mut outcomes))
            } else {
                task.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await
    }
}

/// A borrowing collector owns exactly one executor-waker subscription.
///
/// Member wakers remain installed on their TaskHandles when this guard ends.
/// They still record completion candidates, but must not retain or wake a task
/// which has dropped its join wait. A later collector observes those candidates
/// after installing its own subscription.
pub(super) struct CollectorWait {
    ready: Arc<ReadyMembers>,
    registered: Option<Arc<Waker>>,
}

impl CollectorWait {
    pub(super) fn new(ready: Arc<ReadyMembers>) -> Self {
        Self {
            ready,
            registered: None,
        }
    }

    pub(super) fn refresh(&mut self, waker: &Waker) {
        if self
            .registered
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
        {
            return;
        }

        // Both RawWaker::clone and final destruction can execute arbitrary
        // executor code. Only Arc refcount operations belong under this lock.
        let incoming = Arc::new(waker.clone());
        let retired_slot = self.ready.waiter.lock().replace(Arc::clone(&incoming));
        let retired_owner = self.registered.replace(incoming);
        // Commit BOTH ownership fields before retiring the previous callback:
        // a reentrant notification now sees the new collector, and unwind can
        // remove the new subscription instead of leaving it stranded.
        drop(retired_slot);
        drop(retired_owner);
    }
}

impl Drop for CollectorWait {
    fn drop(&mut self) {
        let Some(registered) = self.registered.take() else {
            return;
        };
        let retired = {
            let mut slot = self.ready.waiter.lock();
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &registered))
            {
                slot.take()
            } else {
                None
            }
        };
        // The local owner also prevents the removal above from invoking an
        // executor destructor under the lock. Never remove a newer owner's slot.
        drop(retired);
        drop(registered);
    }
}

#[cfg(test)]
mod selection_tests {
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
}
