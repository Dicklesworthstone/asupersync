//! Wake-driven observation of a context's cancellation request.
//!
//! A cancellation observer owns an auxiliary registration, not the runtime's
//! cancellation-lane waker. It can therefore be composed with other waits on
//! the same task without replacing their wakeups or keeping dropped tasks alive.

use super::{CancelWakerToken, Cx, cap};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

struct Registration {
    waker: Waker,
    token: CancelWakerToken,
}

/// Future returned by [`Cx::cancelled`].
///
/// Completion means a cancellation request was observed, not acknowledged or
/// drained. Like [`Cx::is_cancel_requested`], observation is mask-agnostic: a
/// caller can begin its own shutdown protocol without acknowledging cancellation
/// or bypassing the masking rules of [`Cx::checkpoint`].
///
/// Each future owns one registration, even when several observers share the
/// same task waker. Completion and drop unregister only that observer. Once a
/// request has been observed, subsequent polls stay ready.
#[must_use = "cancellation observers do nothing unless polled or awaited"]
pub struct Cancelled<'a, Caps = cap::All> {
    cx: &'a Cx<Caps>,
    registration: Option<Registration>,
    observed: bool,
}

impl<Caps> fmt::Debug for Cancelled<'_, Caps> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cancelled")
            .field("registered", &self.registration.is_some())
            .field("observed", &self.observed)
            .finish_non_exhaustive()
    }
}

impl<Caps> Cx<Caps> {
    /// Wait until cancellation is requested, without busy-polling or a timer.
    ///
    /// The first poll installs an owned cancellation-waker registration and
    /// rechecks the request, closing the check/register race. Cancellation
    /// published through the runtime or methods such as [`Self::cancel_fast`]
    /// and [`Self::cancel_with`] wakes a parked observer. Legacy direct writes
    /// to public context fields are not a wake-producing publication mechanism.
    ///
    /// This is a read-only, mask-agnostic observation, just like
    /// [`Self::is_cancel_requested`]. It does not acknowledge cancellation,
    /// charge checkpoint budgets, wait for child tasks, or certify cleanup.
    /// Call [`Self::checkpoint`] when protocol acknowledgement is appropriate.
    /// No spawn, timer, I/O, or other effect capability is required.
    ///
    /// The observer is cancellation-safe: dropping it removes its own wake
    /// registration without clearing the request or affecting another waiter.
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    /// use std::future::Future;
    /// use std::pin::pin;
    /// use std::task::{Context, Waker};
    ///
    /// let cx = Cx::detached_cancel_context();
    /// let mut cancelled = pin!(cx.cancelled());
    /// let mut task = Context::from_waker(Waker::noop());
    /// assert!(cancelled.as_mut().poll(&mut task).is_pending());
    /// cx.cancel_fast(CancelKind::User);
    /// assert!(cancelled.as_mut().poll(&mut task).is_ready());
    /// ```
    pub const fn cancelled(&self) -> Cancelled<'_, Caps> {
        Cancelled {
            cx: self,
            registration: None,
            observed: false,
        }
    }
}

impl<Caps> Cancelled<'_, Caps> {
    fn refresh(&mut self, waker: &Waker) {
        let unchanged = self
            .registration
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        // Waker clone and retirement are user callbacks. Keep our own strong
        // owner until the Cx registry has released its lock in both cases.
        let incoming = if unchanged {
            None
        } else {
            Some(waker.clone())
        };
        let previous = self.registration.as_ref().map(|entry| entry.token);
        let token = self.cx.refresh_cancel_waker(previous, waker);
        let retired = if let Some(waker) = incoming {
            self.registration.replace(Registration { waker, token })
        } else {
            self.registration
                .as_mut()
                .expect("unchanged waker has an owned registration")
                .token = token;
            None
        };
        drop(retired);
    }

    fn unregister(&mut self) {
        if let Some(registered) = self.registration.take() {
            self.cx.clear_cancel_waker(registered.token);
            drop(registered);
        }
    }

    fn finish(&mut self) -> Poll<()> {
        // Commit terminal state before a user waker destructor can unwind.
        self.observed = true;
        self.unregister();
        Poll::Ready(())
    }
}

impl<Caps> Future for Cancelled<'_, Caps> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.observed || this.cx.is_cancel_requested() {
            return this.finish();
        }
        this.refresh(task.waker());
        if this.cx.is_cancel_requested() {
            this.finish()
        } else {
            Poll::Pending
        }
    }
}

impl<Caps> Drop for Cancelled<'_, Caps> {
    fn drop(&mut self) {
        self.unregister();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CancelKind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Wake;

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

    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    fn registrations<Caps>(cx: &Cx<Caps>) -> usize {
        cx.inner.read().cancel_waker_registrations.len()
    }

    #[test]
    fn construction_is_lazy_and_pre_cancelled_poll_does_not_register() {
        let cx = Cx::for_testing();
        let mut wait = Box::pin(cx.cancelled());
        assert_eq!(registrations(&cx), 0);
        cx.cancel_fast(CancelKind::User);
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(registrations(&cx), 0);
        assert!(!cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn parked_observer_is_woken_then_unregisters_on_completion() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 1);
        cx.cancel_fast(CancelKind::User);
        // Verify notification before any manual repoll can hide a lost wake.
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
        assert!(!cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn every_public_request_publisher_wakes_an_observer() {
        for publisher in 0..4 {
            let cx = Cx::for_testing();
            let (count, waker) = counter();
            let mut task = Context::from_waker(&waker);
            let mut wait = Box::pin(cx.cancelled());
            assert!(wait.as_mut().poll(&mut task).is_pending());
            match publisher {
                0 => cx.cancel_fast(CancelKind::User),
                1 => cx.cancel_with(CancelKind::User, Some("observer test")),
                2 => cx.set_cancel_requested(true),
                _ => cx.set_cancel_reason(crate::types::CancelReason::new(CancelKind::User)),
            }
            assert!(count.0.load(Ordering::SeqCst) > 0);
            assert!(wait.as_mut().poll(&mut task).is_ready());
            assert_eq!(registrations(&cx), 0);
        }
    }

    #[test]
    fn dropping_one_same_waker_observer_preserves_the_other_owner() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut first = Box::pin(cx.cancelled());
        let mut second = Box::pin(cx.cancelled());
        assert!(first.as_mut().poll(&mut task).is_pending());
        assert!(second.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 2);
        drop(first);
        assert_eq!(registrations(&cx), 1);
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(second.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn unchanged_repolls_reuse_one_owned_registration() {
        let cx = Cx::for_testing();
        let (_, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        let token = wait.registration.as_ref().unwrap().token;
        for _ in 0..64 {
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert_eq!(wait.registration.as_ref().unwrap().token, token);
            assert_eq!(registrations(&cx), 1);
        }
        drop(wait);
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn task_migration_refreshes_the_waker_without_leaking_entries() {
        let cx = Cx::for_testing();
        let (old, old_waker) = counter();
        let (new, new_waker) = counter();
        let mut wait = Box::pin(cx.cancelled());
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&new_waker))
                .is_pending()
        );
        assert_eq!(registrations(&cx), 1);
        cx.cancel_fast(CancelKind::User);
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert!(new.0.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn drop_retires_task_payload_outside_the_context_lock() {
        struct ReenterDrop {
            cx: Cx,
            retired_unlocked: Arc<AtomicBool>,
        }
        impl Wake for ReenterDrop {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for ReenterDrop {
            fn drop(&mut self) {
                self.retired_unlocked
                    .store(self.cx.inner.try_write().is_some(), Ordering::SeqCst);
            }
        }
        let cx = Cx::for_testing();
        let retired_unlocked = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(ReenterDrop {
            cx: cx.clone(),
            retired_unlocked: retired_unlocked.clone(),
        }));
        let mut wait = Box::pin(cx.cancelled());
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(waker);
        drop(wait);
        assert_eq!(registrations(&cx), 0);
        assert!(retired_unlocked.load(Ordering::SeqCst));
    }

    #[test]
    fn mask_agnostic_observation_does_not_acknowledge_cancellation() {
        let cx = Cx::for_testing();
        let mut wait = Box::pin(cx.cancelled());
        cx.cancel_fast(CancelKind::User);
        cx.masked(|| {
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            assert!(cx.checkpoint().is_ok());
            assert!(!cx.inner.read().cancel_acknowledged);
        });
        assert!(!cx.inner.read().cancel_acknowledged);
        assert!(cx.checkpoint().is_err());
        assert!(cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn completed_observer_stays_ready_after_test_only_request_reset() {
        let cx = Cx::for_testing();
        let mut wait = Box::pin(cx.cancelled());
        let mut task = Context::from_waker(Waker::noop());
        cx.cancel_fast(CancelKind::User);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        cx.set_cancel_requested(false);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn detached_no_capability_context_supports_wake_driven_observation() {
        let cx = Cx::detached_cancel_context();
        let (count, waker) = counter();
        let mut wait = Box::pin(cx.cancelled());
        let mut task = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut task).is_pending());
        cx.cancel_with(CancelKind::User, None);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn cancellation_racing_first_registration_cannot_leave_an_unwoken_waiter() {
        for _ in 0..64 {
            let cx = Cx::for_testing();
            let (count, waker) = counter();
            let mut wait = Box::pin(cx.cancelled());
            let first_poll = std::thread::scope(|scope| {
                scope.spawn(|| cx.cancel_fast(CancelKind::User));
                wait.as_mut().poll(&mut Context::from_waker(&waker))
            });
            // The cancellation thread has joined. Either the first poll saw
            // its request or its owned registration must have been notified.
            if first_poll.is_pending() {
                assert!(count.0.load(Ordering::SeqCst) > 0);
            }
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            assert_eq!(registrations(&cx), 0);
        }
    }
}
