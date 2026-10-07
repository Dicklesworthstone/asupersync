//! Lifetime of the task waiting for a member, separate from member readiness.

use super::ReadyMembers;
use std::sync::Arc;
use std::task::Waker;

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
