//! Cancellation-owned admission to the bounded fallback-thread path.
//!
//! The global queue contains a distinct relay for each admission, not a task's
//! waker directly. Sharing a task waker therefore cannot merge two independent
//! waits, and dropping a wait retires its registration even if all worker
//! threads remain blocked forever. Waker replacement, destruction and wake
//! callbacks run outside both the queue mutex and the relay mutex.

use super::{poll_claim_fallback_slot, try_claim_fallback_slot};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Wake, Waker};

struct AdmissionWake {
    target: Mutex<Option<Waker>>,
}

impl AdmissionWake {
    fn refresh(&self, waker: &Waker) {
        let incoming = waker.clone();
        let retired = self.target.lock().replace(incoming);
        drop(retired);
    }

    fn notify(&self) {
        let target = self.target.lock().take();
        if let Some(target) = target {
            target.wake();
        }
    }
}

impl Wake for AdmissionWake {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

struct Registration {
    relay: Arc<AdmissionWake>,
    waker: Waker,
}

/// One pending claim. A successful claim transfers its slot to the caller;
/// dropping an unsuccessful claim removes only this admission's registration.
pub(super) struct FallbackAdmission<'a> {
    count: &'a AtomicUsize,
    cap: usize,
    waiters: &'a Mutex<VecDeque<Waker>>,
    registration: Option<Registration>,
    completed: bool,
}

impl<'a> FallbackAdmission<'a> {
    pub(super) const fn new(
        count: &'a AtomicUsize,
        cap: usize,
        waiters: &'a Mutex<VecDeque<Waker>>,
    ) -> Self {
        Self {
            count,
            cap,
            waiters,
            registration: None,
            completed: false,
        }
    }

    fn unregister(&mut self) {
        if let Some(registration) = self.registration.take() {
            let removed = {
                let mut waiters = self.waiters.lock();
                let index = waiters
                    .iter()
                    .position(|waker| waker.will_wake(&registration.waker));
                index.and_then(|index| waiters.remove(index))
            };
            // A concurrent release may already own the relay. Clearing its
            // target still severs task ownership; an already-taken wake may
            // run once, but can neither retain nor re-register this wait.
            let target = registration.relay.target.lock().take();
            drop(removed);
            drop(target);
        }
    }
}

impl Future for FallbackAdmission<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        assert!(!this.completed, "fallback admission polled after completion");
        // No relay allocation or waker cloning on uncontended admission.
        if try_claim_fallback_slot(this.count, this.cap) {
            this.completed = true;
            this.unregister();
            return Poll::Ready(());
        }
        let registration = this.registration.get_or_insert_with(|| {
            let relay = Arc::new(AdmissionWake {
                target: Mutex::new(None),
            });
            let waker = Waker::from(Arc::clone(&relay));
            Registration { relay, waker }
        });
        registration.relay.refresh(context.waker());
        let relay_context = Context::from_waker(&registration.waker);
        let result = poll_claim_fallback_slot(this.count, this.cap, this.waiters, &relay_context);
        if result.is_ready() {
            this.completed = true;
            this.unregister();
        }
        result
    }
}

impl Drop for FallbackAdmission<'_> {
    fn drop(&mut self) {
        self.unregister();
    }
}

#[cfg(test)]
#[path = "fallback_admission_tests.rs"]
mod tests;
