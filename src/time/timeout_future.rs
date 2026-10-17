//! Timeout wrapper for futures.
//!
//! The [`TimeoutFuture`] wraps another future and limits how long it can run.

use super::elapsed::Elapsed;
use super::sleep::Sleep;
use crate::types::Time;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

#[inline]
fn ambient_timer_now() -> Option<Time> {
    crate::cx::Cx::current()
        .and_then(|cx| cx.timer_driver())
        .map(|timer| timer.now())
}

/// A future that wraps another future with a timeout.
///
/// If the inner future doesn't complete before the deadline, `TimeoutFuture`
/// resolves to `Err(Elapsed)`. If it completes in time, it resolves to
/// `Ok(F::Output)`.
///
/// # Type Parameters
///
/// * `F` - The inner future type.
///
/// # Cancel Safety
///
/// `TimeoutFuture` is cancel-safe in the sense that dropping it is safe.
/// However, if the inner future has side effects that occur during polling,
/// those may be partially applied.
/// An owner's cancellation remains visible to the inner future; it does not
/// itself expire the timeout. Pending cancellation cleanup may continue until
/// the actual deadline, which still bounds an unresponsive inner future.
///
/// # Example
///
/// ```ignore
/// use asupersync::time::timeout;
/// use std::time::Duration;
///
/// async fn slow_operation() -> u32 {
///     // ... takes a long time ...
///     42
/// }
///
/// let result = timeout(Time::ZERO, Duration::from_secs(5), slow_operation()).await;
/// match result {
///     Ok(value) => println!("Got: {value}"),
///     Err(_) => println!("Operation timed out!"),
/// }
/// ```
#[derive(Debug)]
#[pin_project]
pub struct TimeoutFuture<F> {
    /// The inner future.
    #[pin]
    future: F,
    /// The sleep future for the timeout.
    sleep: Sleep,
    /// Set once a terminal result has been returned and cleared only when
    /// a timeout result is explicitly reset for reuse.
    completed: bool,
    /// Tracks whether the last terminal result was a timeout, which is the
    /// only terminal state that `reset` can safely re-arm.
    timed_out: bool,
}

impl<F> TimeoutFuture<F> {
    /// Creates a new timeout wrapper.
    ///
    /// # Arguments
    ///
    /// * `future` - The future to wrap
    /// * `deadline` - When the timeout expires
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::TimeoutFuture;
    /// use asupersync::types::Time;
    /// use std::future::ready;
    ///
    /// let future = ready(42);
    /// let timeout = TimeoutFuture::new(future, Time::from_secs(5));
    /// assert_eq!(timeout.deadline(), Time::from_secs(5));
    /// ```
    #[must_use]
    pub fn new(future: F, deadline: Time) -> Self {
        Self {
            future,
            sleep: Sleep::new(deadline),
            completed: false,
            timed_out: false,
        }
    }

    /// Creates a new timeout wrapper with an explicit time getter.
    ///
    /// This is useful for deterministic tests and synthetic clocks that
    /// should not rely on wall-clock progression.
    #[must_use]
    pub fn with_time_getter(future: F, deadline: Time, time_getter: fn() -> Time) -> Self {
        Self {
            future,
            sleep: Sleep::with_time_getter(deadline, time_getter),
            completed: false,
            timed_out: false,
        }
    }

    /// Creates a timeout that expires after the given duration.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `duration` - How long until timeout
    /// * `future` - The future to wrap
    #[must_use]
    pub fn after(now: Time, duration: Duration, future: F) -> Self {
        Self {
            future,
            sleep: Sleep::after(now, duration),
            completed: false,
            timed_out: false,
        }
    }

    /// Returns the timeout deadline.
    #[must_use]
    #[inline]
    pub const fn deadline(&self) -> Time {
        self.sleep.deadline()
    }

    /// Returns the remaining time until timeout.
    ///
    /// Returns `Duration::ZERO` if the timeout has elapsed.
    #[must_use]
    #[inline]
    pub fn remaining(&self, now: Time) -> Duration {
        self.sleep.remaining(now)
    }

    /// Returns true if the timeout has elapsed.
    #[must_use]
    #[inline]
    pub fn is_elapsed(&self, now: Time) -> bool {
        self.sleep.is_elapsed(now)
    }

    /// Returns a reference to the inner future.
    #[must_use]
    #[inline]
    pub const fn inner(&self) -> &F {
        &self.future
    }

    /// Returns a mutable reference to the inner future.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut F {
        &mut self.future
    }

    /// Consumes the timeout, returning the inner future.
    ///
    /// Note: This discards the timeout and lets the future run indefinitely.
    #[must_use]
    #[inline]
    pub fn into_inner(self) -> F {
        self.future
    }

    /// Resets the timeout to a new deadline.
    ///
    /// This can re-arm an uncompleted timeout or one that previously elapsed.
    /// It deliberately does not re-arm after the inner future has completed,
    /// because `TimeoutFuture` cannot replace a consumed inner future.
    pub fn reset(&mut self, deadline: Time) {
        if self.completed && !self.timed_out {
            return;
        }
        self.completed = false;
        self.timed_out = false;
        self.sleep.reset(deadline);
    }

    /// Resets the timeout to expire after the given duration.
    pub fn reset_after(&mut self, now: Time, duration: Duration) {
        if self.completed && !self.timed_out {
            return;
        }
        self.completed = false;
        self.timed_out = false;
        self.sleep.reset_after(now, duration);
    }
}

impl<F: Future + Unpin> TimeoutFuture<F> {
    /// Polls the timeout future with an explicit time value.
    ///
    /// This is useful when you want to control the time source manually.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `cx` - The task context for the inner future
    ///
    /// # Returns
    ///
    /// - `Poll::Ready(Ok(output))` if the inner future completed
    /// - `Poll::Ready(Err(Elapsed))` if the timeout elapsed
    /// - `Poll::Pending` if neither has occurred yet
    pub fn poll_with_time(
        &mut self,
        cx: &mut Context<'_>,
        now: Time,
    ) -> Poll<Result<F::Output, Elapsed>> {
        // Fail-closed: repoll after completion returns Elapsed instead of
        // panicking so callers see a deterministic error.
        if self.completed || self.timed_out {
            return Poll::Ready(Err(Elapsed::new(self.sleep.deadline())));
        }
        let deadline = self.sleep.deadline();
        if now > deadline && self.sleep.poll_ready_with_time(now).is_ready() {
            self.completed = true;
            self.timed_out = true;
            return Poll::Ready(Err(Elapsed::new(deadline)));
        }

        // Prefer completed work at the exact timeout boundary. This preserves
        // the crate-wide contract that a ready inner future is not lost just
        // because the timeout boundary is observed in the same scheduler turn.
        // SAFETY: We require F: Unpin, so this is safe
        match Pin::new(&mut self.future).poll(cx) {
            Poll::Ready(output) => {
                self.completed = true;
                self.timed_out = false;
                return Poll::Ready(Ok(output));
            }
            Poll::Pending => {}
        }

        if self.sleep.poll_ready_with_time(now).is_ready() {
            self.completed = true;
            self.timed_out = true;
            return Poll::Ready(Err(Elapsed::new(deadline)));
        }

        // Preserve wake registration only when the underlying sleep can use
        // the same time domain as the explicit `now`. Falling back to a
        // wall-clock sleep here makes manual/virtual-time polls observe an
        // unrelated clock and can spuriously expire after long test suites.
        if self.sleep.has_custom_time_getter() || self.sleep.has_timer_driver_for_poll() {
            match Pin::new(&mut self.sleep).poll_deadline(cx) {
                Poll::Ready(()) => {
                    self.completed = true;
                    self.timed_out = true;
                    return Poll::Ready(Err(Elapsed::new(self.sleep.deadline())));
                }
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }
}

impl<F: Future> Future for TimeoutFuture<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        // Fail-closed: repoll after completion returns Elapsed instead of
        // panicking so callers that accidentally hold a reference see a
        // deterministic error rather than unwinding.
        if *this.completed || *this.timed_out {
            return Poll::Ready(Err(Elapsed::new(this.sleep.deadline())));
        }

        let deadline = this.sleep.deadline();
        if let Some(now) = deadline_clock_now(this.sleep)
            && now > deadline
            && this.sleep.poll_ready_with_time(now).is_ready()
        {
            *this.completed = true;
            *this.timed_out = true;
            return Poll::Ready(Err(Elapsed::new(deadline)));
        }

        // Prefer completed work at the exact timeout boundary.
        match this.future.poll(cx) {
            Poll::Ready(output) => {
                *this.completed = true;
                *this.timed_out = false;
                return Poll::Ready(Ok(output));
            }
            Poll::Pending => {}
        }

        match Pin::new(this.sleep).poll_deadline(cx) {
            Poll::Ready(()) => {
                *this.completed = true;
                *this.timed_out = true;
                Poll::Ready(Err(Elapsed::new(deadline)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F: Clone> Clone for TimeoutFuture<F> {
    fn clone(&self) -> Self {
        Self {
            future: self.future.clone(),
            sleep: self.sleep.clone(),
            completed: self.completed,
            timed_out: self.timed_out,
        }
    }
}

/// Creates a `TimeoutFuture` that wraps the given future with a timeout.
///
/// # Arguments
///
/// * `now` - The current time
/// * `duration` - How long until the timeout expires
/// * `future` - The future to wrap
///
/// # Example
///
/// ```
/// use asupersync::time::timeout;
/// use asupersync::types::Time;
/// use std::time::Duration;
/// use std::future::ready;
///
/// let future = timeout(Time::ZERO, Duration::from_secs(5), ready(42));
/// assert_eq!(future.deadline(), Time::from_secs(5));
/// ```
#[must_use]
pub fn timeout<F>(now: Time, duration: Duration, future: F) -> TimeoutFuture<F> {
    TimeoutFuture::after(now, duration, future)
}

/// Creates a `TimeoutFuture` that wraps the given future with a deadline.
///
/// # Arguments
///
/// * `deadline` - The absolute time when the timeout expires
/// * `future` - The future to wrap
///
/// # Example
///
/// ```
/// use asupersync::time::timeout_at;
/// use asupersync::types::Time;
/// use std::future::ready;
///
/// let future = timeout_at(Time::from_secs(10), ready(42));
/// assert_eq!(future.deadline(), Time::from_secs(10));
/// ```
#[must_use]
pub fn timeout_at<F>(deadline: Time, future: F) -> TimeoutFuture<F> {
    TimeoutFuture::new(future, deadline)
}

/// The ambient runtime timer's now, for the expired-deadline check before the
/// inner future is polled; `None` when the sleep keeps its own clock. A custom
/// clock's deadline is checked by the sleep itself, after the inner future, as
/// it always was: comparing it here with the runtime timer (a test clock
/// starting at zero, or any clock not anchored to the runtime's) expired a
/// deadline the custom clock had not reached before the inner future was polled.
fn deadline_clock_now(sleep: &Sleep) -> Option<Time> {
    if sleep.time_getter.is_some() {
        None
    } else {
        ambient_timer_now()
    }
}

#[cfg(test)]
#[path = "timeout_future_inline_tests.rs"]
mod tests;
