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
///
/// # Task Lifecycle & Completion
///
/// While the context's task is live, cancellation requests wake registered
/// observers. When a task completes, its cancellation-waker registry is closed
/// (`cancel_waker_registry_closed`) and any registered observers are retired.
/// They are woken only if a request published before completion had not
/// reached them yet. A cancellation request published to a context after its
/// task has already completed does not wake observers (since no active
/// registrations remain, and new registrations are rejected with a token of 0).
/// However, if cancellation is requested post-completion, any subsequent poll
/// of [`Cancelled`] will immediately observe the request and return [`Poll::Ready`].
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
    /// and [`Self::cancel_with`] wakes a parked observer while the context's
    /// task is live. Legacy direct writes to public context fields are not a
    /// wake-producing publication mechanism.
    ///
    /// # Task Lifecycle & Completion Semantics
    ///
    /// When a task completes and its record reaches terminal retirement, the
    /// runtime detaches its cancellation-waker registry
    /// (`cancel_waker_registry_closed`). Parked observers are retired; a
    /// request published before completion whose wakes were still deferred is
    /// delivered to them first. Subsequent calls to [`Self::cancel_fast`] or [`Self::cancel_with`]
    /// on the finished task's context do not wake observers (since no active
    /// waker registrations remain). Additionally, completed contexts reject new
    /// waker registrations (returning a zero token).
    ///
    /// However, if cancellation was requested before or after completion, any
    /// subsequent poll of [`Self::cancelled`] or check of [`Self::is_cancel_requested`]
    /// will immediately observe the request and resolve [`Poll::Ready`].
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
        let incoming = if unchanged { None } else { Some(waker.clone()) };
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
#[path = "cancelled_inline_tests.rs"]
mod tests;
