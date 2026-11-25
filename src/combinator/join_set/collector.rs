//! Lifetime of the task waiting for a member, separate from member readiness.

#[cfg(test)]
use super::Outcome;
use super::{CollectedMember, JoinSet, Policy, ReadyMembers, join_to_outcome};
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
    pub(in crate::combinator) async fn next_member_bounded(
        &mut self,
        remaining: &mut usize,
    ) -> Option<CollectedMember<T, E>> {
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
                if let Some(member) = self.poll_candidate_member(index) {
                    return Poll::Ready(Some(member));
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

    #[cfg(test)]
    async fn next_outcome_bounded(&mut self, remaining: &mut usize) -> Option<Outcome<T, E>> {
        self.next_member_bounded(remaining)
            .await
            .map(|member| member.outcome)
    }

    /// Cancel every unfinished member before awaiting any retirement, then
    /// collect in bounded spawn-order batches. Published outcomes are immutable
    /// even while their retirement barrier is closed. Legacy explicit-abort
    /// APIs retain their separate reason-strengthening behavior.
    pub(in crate::combinator) async fn cancel_members_for_selection(
        self,
        reason: CancelReason,
    ) -> Vec<CollectedMember<T, E>> {
        let mut outcomes = Vec::with_capacity(self.members.len());
        // On drop or unwind, request the remaining cancellations before user
        // values in the collected prefix are destroyed (v8rp1h L6).
        let mut members = self;
        members.cancel_unfinished_for_owner(&reason);
        poll_fn(|task| {
            for _ in 0..Self::SELECTION_CANDIDATES_PER_POLL {
                let Some((&index, _)) = members.members.first_key_value() else {
                    return Poll::Ready(std::mem::take(&mut outcomes));
                };
                let member = members
                    .members
                    .get_mut(&index)
                    .expect("first member remains owned");
                let joined = member.handle.poll_join(task);
                let Poll::Ready(joined) = joined else {
                    return Poll::Pending;
                };
                // Admission can replace a provisional mailbox identity while
                // the join is pending. Capture the published identity only
                // after the outcome and retirement barrier are ready.
                let task_id = member.handle.task_id();
                let outcome = join_to_outcome(joined);
                members.take_member(index, &outcome);
                outcomes.push(CollectedMember {
                    index,
                    task_id,
                    outcome,
                });
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

    #[cfg(test)]
    async fn cancel_remaining_for_selection(self, reason: CancelReason) -> Vec<Outcome<T, E>> {
        self.cancel_members_for_selection(reason)
            .await
            .into_iter()
            .map(|member| member.outcome)
            .collect()
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

    /// Retire the subscription while retaining its final executor-waker owner.
    /// A completing poll must publish its result before a foreign destructor
    /// can run; the owner is released when this guard itself is dropped.
    pub(super) fn clear(&mut self) {
        let Some(registered) = self.registered.as_ref() else {
            return;
        };
        let retired = {
            let mut slot = self.ready.waiter.lock();
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, registered))
            {
                slot.take()
            } else {
                None
            }
        };
        // The local owner also prevents the removal above from invoking an
        // executor destructor under the lock. Never remove a newer owner's slot.
        drop(retired);
    }
}

impl Drop for CollectorWait {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
#[path = "collector_selection_tests_inline_tests.rs"]
mod selection_tests;
