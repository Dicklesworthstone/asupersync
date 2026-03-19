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
    pub const fn deadline(&self) -> Time {
        self.sleep.deadline()
    }

    /// Returns the remaining time until timeout.
    ///
    /// Returns `Duration::ZERO` if the timeout has elapsed.
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        self.sleep.remaining(now)
    }

    /// Returns true if the timeout has elapsed.
    #[must_use]
    pub fn is_elapsed(&self, now: Time) -> bool {
        self.sleep.is_elapsed(now)
    }

    /// Returns a reference to the inner future.
    #[must_use]
    pub const fn inner(&self) -> &F {
        &self.future
    }

    /// Returns a mutable reference to the inner future.
    pub fn inner_mut(&mut self) -> &mut F {
        &mut self.future
    }

    /// Consumes the timeout, returning the inner future.
    ///
    /// Note: This discards the timeout and lets the future run indefinitely.
    #[must_use]
    pub fn into_inner(self) -> F {
        self.future
    }

    /// Resets the timeout to a new deadline.
    pub fn reset(&mut self, deadline: Time) {
        self.completed = false;
        self.timed_out = false;
        self.sleep.reset(deadline);
    }

    /// Resets the timeout to expire after the given duration.
    pub fn reset_after(&mut self, now: Time, duration: Duration) {
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
        // Poll the inner future first — if it's ready, return its result
        // even if the timeout has also elapsed, to avoid losing completed work.
        // SAFETY: We require F: Unpin, so this is safe
        match Pin::new(&mut self.future).poll(cx) {
            Poll::Ready(output) => {
                self.completed = true;
                self.timed_out = false;
                return Poll::Ready(Ok(output));
            }
            Poll::Pending => {}
        }

        // Check the timeout explicitly using the provided time
        if self.sleep.poll_with_time(now).is_ready() {
            self.completed = true;
            self.timed_out = true;
            return Poll::Ready(Err(Elapsed::new(self.sleep.deadline())));
        }

        // Preserve wake registration only when the underlying sleep can use
        // the same time domain as the explicit `now`. Falling back to a
        // wall-clock sleep here makes manual/virtual-time polls observe an
        // unrelated clock and can spuriously expire after long test suites.
        let has_ambient_timer = crate::cx::Cx::current()
            .and_then(|current| current.timer_driver())
            .is_some();
        if self.sleep.has_custom_time_getter() || has_ambient_timer {
            match Pin::new(&mut self.sleep).poll(cx) {
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

        // Poll the inner future first — if it's ready, we should return its
        // result even if the timeout has also elapsed. This avoids losing
        // completed work at the boundary.
        match this.future.poll(cx) {
            Poll::Ready(output) => {
                *this.completed = true;
                *this.timed_out = false;
                return Poll::Ready(Ok(output));
            }
            Poll::Pending => {}
        }

        // Poll the sleep future to register wakeup (e.g. background thread in standalone mode)
        let deadline = this.sleep.deadline();
        match Pin::new(this.sleep).poll(cx) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::future::Future;
    use std::future::{pending, ready};
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    // =========================================================================
    // Construction Tests
    // =========================================================================

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    // Each test that needs a shared time source should use thread_local!
    // to avoid races when tests run in parallel.
    thread_local! {
        static CURRENT_TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_current_time(nanos: u64) {
        CURRENT_TIME.with(|t| t.set(nanos));
    }

    fn get_current_time() -> u64 {
        CURRENT_TIME.with(std::cell::Cell::get)
    }

    struct CountingFuture {
        count: u32,
        ready_at: u32,
    }

    impl Future for CountingFuture {
        type Output = &'static str;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.count += 1;
            if self.count >= self.ready_at {
                Poll::Ready("done")
            } else {
                Poll::Pending
            }
        }
    }

    impl Unpin for CountingFuture {}

    #[test]
    fn new_creates_timeout() {
        init_test("new_creates_timeout");
        let future = ready(42);
        let timeout = TimeoutFuture::new(future, Time::from_secs(5));
        crate::assert_with_log!(
            timeout.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            timeout.deadline()
        );
        crate::test_complete!("new_creates_timeout");
    }

    #[test]
    fn after_computes_deadline() {
        init_test("after_computes_deadline");
        let future = ready(42);
        let timeout = TimeoutFuture::after(Time::from_secs(10), Duration::from_secs(5), future);
        crate::assert_with_log!(
            timeout.deadline() == Time::from_secs(15),
            "deadline",
            Time::from_secs(15),
            timeout.deadline()
        );
        crate::test_complete!("after_computes_deadline");
    }

    #[test]
    fn timeout_function() {
        init_test("timeout_function");
        let t = timeout(Time::from_secs(10), Duration::from_secs(3), ready(42));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(13),
            "deadline",
            Time::from_secs(13),
            t.deadline()
        );
        crate::test_complete!("timeout_function");
    }

    #[test]
    fn timeout_at_function() {
        init_test("timeout_at_function");
        let t = timeout_at(Time::from_secs(42), ready(123));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(42),
            "deadline",
            Time::from_secs(42),
            t.deadline()
        );
        crate::test_complete!("timeout_at_function");
    }

    // =========================================================================
    // Accessor Tests
    // =========================================================================

    #[test]
    fn remaining_before_deadline() {
        init_test("remaining_before_deadline");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let remaining = t.remaining(Time::from_secs(7));
        crate::assert_with_log!(
            remaining == Duration::from_secs(3),
            "remaining",
            Duration::from_secs(3),
            remaining
        );
        crate::test_complete!("remaining_before_deadline");
    }

    #[test]
    fn remaining_after_deadline() {
        init_test("remaining_after_deadline");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let remaining = t.remaining(Time::from_secs(15));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_after_deadline");
    }

    #[test]
    fn is_elapsed() {
        init_test("is_elapsed");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        crate::assert_with_log!(
            !t.is_elapsed(Time::from_secs(5)),
            "not elapsed at t=5",
            false,
            t.is_elapsed(Time::from_secs(5))
        );
        crate::assert_with_log!(
            t.is_elapsed(Time::from_secs(10)),
            "elapsed at t=10",
            true,
            t.is_elapsed(Time::from_secs(10))
        );
        crate::assert_with_log!(
            t.is_elapsed(Time::from_secs(15)),
            "elapsed at t=15",
            true,
            t.is_elapsed(Time::from_secs(15))
        );
        crate::test_complete!("is_elapsed");
    }

    #[test]
    fn inner() {
        init_test("inner");
        let future = ready(42);
        let t = TimeoutFuture::new(future, Time::from_secs(5));
        let _ = t.inner(); // Just check it compiles
        crate::test_complete!("inner");
    }

    #[test]
    fn inner_mut() {
        init_test("inner_mut");
        let future = ready(42);
        let mut t = TimeoutFuture::new(future, Time::from_secs(5));
        let _inner = t.inner_mut(); // Just check it compiles
        crate::test_complete!("inner_mut");
    }

    #[test]
    fn into_inner() {
        init_test("into_inner");
        let future = ready(42);
        let t = TimeoutFuture::new(future, Time::from_secs(5));
        let _inner = t.into_inner();
        crate::test_complete!("into_inner");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_changes_deadline() {
        init_test("reset_changes_deadline");
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(5));
        t.reset(Time::from_secs(10));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            t.deadline()
        );
        crate::test_complete!("reset_changes_deadline");
    }

    #[test]
    fn reset_after_changes_deadline() {
        init_test("reset_after_changes_deadline");
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(5));
        t.reset_after(Time::from_secs(3), Duration::from_secs(7));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            t.deadline()
        );
        crate::test_complete!("reset_after_changes_deadline");
    }

    // =========================================================================
    // poll_with_time Tests
    // =========================================================================

    #[test]
    fn poll_with_time_future_completes() {
        init_test("poll_with_time_future_completes");
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is before deadline, future is ready
        let result = t.poll_with_time(&mut cx, Time::from_secs(5));
        let ready = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(ready, "ready ok", true, ready);
        crate::test_complete!("poll_with_time_future_completes");
    }

    #[test]
    fn poll_with_time_timeout_elapsed() {
        init_test("poll_with_time_timeout_elapsed");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is past deadline
        let result = t.poll_with_time(&mut cx, Time::from_secs(15));
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);

        if let Poll::Ready(Err(elapsed)) = result {
            crate::assert_with_log!(
                elapsed.deadline() == Time::from_secs(10),
                "deadline",
                Time::from_secs(10),
                elapsed.deadline()
            );
        }
        crate::test_complete!("poll_with_time_timeout_elapsed");
    }

    #[test]
    fn poll_with_time_pending() {
        init_test("poll_with_time_pending");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is before deadline, future is pending
        let result = t.poll_with_time(&mut cx, Time::from_secs(5));
        crate::assert_with_log!(result.is_pending(), "pending", true, result.is_pending());
        crate::test_complete!("poll_with_time_pending");
    }

    #[test]
    fn poll_with_time_at_exact_deadline() {
        init_test("poll_with_time_at_exact_deadline");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is exactly at deadline
        let result = t.poll_with_time(&mut cx, Time::from_secs(10));
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed at deadline", true, elapsed);
        crate::test_complete!("poll_with_time_at_exact_deadline");
    }

    #[test]
    fn poll_with_time_zero_deadline() {
        init_test("poll_with_time_zero_deadline");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Even at time zero, deadline is reached
        let result = t.poll_with_time(&mut cx, Time::ZERO);
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed at zero", true, elapsed);
        crate::test_complete!("poll_with_time_zero_deadline");
    }

    #[test]
    fn poll_with_time_returns_elapsed_after_success_completion() {
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = t.poll_with_time(&mut cx, Time::from_secs(5));
        assert!(matches!(first, Poll::Ready(Ok(42))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = t.poll_with_time(&mut cx, Time::from_secs(6));
        assert!(matches!(repoll, Poll::Ready(Err(_))));
    }

    #[test]
    fn poll_with_time_returns_elapsed_after_timeout_until_reset() {
        set_current_time(0);
        let future = CountingFuture {
            count: 0,
            ready_at: 3,
        };
        let mut t = TimeoutFuture::with_time_getter(future, Time::from_secs(5), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(t.poll_with_time(&mut cx, Time::from_secs(0)).is_pending());

        let elapsed = t.poll_with_time(&mut cx, Time::from_secs(10));
        assert!(matches!(elapsed, Poll::Ready(Err(_))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = t.poll_with_time(&mut cx, Time::from_secs(11));
        assert!(matches!(repoll, Poll::Ready(Err(_))));

        t.reset(Time::from_secs(20));
        let resumed = t.poll_with_time(&mut cx, Time::from_secs(12));
        assert!(matches!(resumed, Poll::Ready(Ok("done"))));
    }

    fn test_now() -> Time {
        Time::from_nanos(get_current_time())
    }

    #[test]
    fn poll_returns_elapsed_after_success_completion() {
        set_current_time(0);
        let mut t = TimeoutFuture::with_time_getter(ready(42), Time::from_secs(10), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(42))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(repoll, Poll::Ready(Err(_))));
    }

    #[test]
    fn poll_returns_elapsed_after_timeout_until_reset() {
        set_current_time(0);
        let future = CountingFuture {
            count: 0,
            ready_at: 3,
        };
        let mut t = TimeoutFuture::with_time_getter(future, Time::from_secs(5), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut t).poll(&mut cx).is_pending());

        set_current_time(10_000_000_000);
        let elapsed = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(elapsed, Poll::Ready(Err(_))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(repoll, Poll::Ready(Err(_))));

        t.reset(Time::from_secs(20));
        set_current_time(12_000_000_000);
        let resumed = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(resumed, Poll::Ready(Ok("done"))));
    }

    // =========================================================================
    // Clone Tests
    // =========================================================================

    #[test]
    fn clone_copies_deadline_and_future() {
        init_test("clone_copies_deadline_and_future");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let t2 = t.clone();
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(10),
            "t deadline",
            Time::from_secs(10),
            t.deadline()
        );
        crate::assert_with_log!(
            t2.deadline() == Time::from_secs(10),
            "t2 deadline",
            Time::from_secs(10),
            t2.deadline()
        );
        crate::test_complete!("clone_copies_deadline_and_future");
    }

    // =========================================================================
    // Integration Scenario Tests
    // =========================================================================

    #[test]
    fn simulated_timeout_scenario() {
        init_test("simulated_timeout_scenario");
        set_current_time(0);
        // Simulate a scenario where we poll multiple times as time advances

        let mut t = TimeoutFuture::with_time_getter(pending::<i32>(), Time::from_secs(5), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // t=0: pending
        let pending = t.poll_with_time(&mut cx, Time::ZERO).is_pending();
        crate::assert_with_log!(pending, "pending at t=0", true, pending);

        // t=2: still pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(2)).is_pending();
        crate::assert_with_log!(pending, "pending at t=2", true, pending);

        // t=4: still pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(4)).is_pending();
        crate::assert_with_log!(pending, "pending at t=4", true, pending);

        // t=5: timeout!
        let result = t.poll_with_time(&mut cx, Time::from_secs(5));
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed at t=5", true, elapsed);
        crate::test_complete!("simulated_timeout_scenario");
    }

    #[test]
    fn simulated_success_scenario() {
        init_test("simulated_success_scenario");
        // Future that completes on the 3rd poll
        let future = CountingFuture {
            count: 0,
            ready_at: 3,
        };
        let mut t = TimeoutFuture::new(future, Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll 1: pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(1)).is_pending();
        crate::assert_with_log!(pending, "pending at t=1", true, pending);

        // Poll 2: pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(2)).is_pending();
        crate::assert_with_log!(pending, "pending at t=2", true, pending);

        // Poll 3: ready!
        let result = t.poll_with_time(&mut cx, Time::from_secs(3));
        let ready = matches!(result, Poll::Ready(Ok("done")));
        crate::assert_with_log!(ready, "ready at t=3", true, ready);
        crate::test_complete!("simulated_success_scenario");
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    use std::sync::Arc;
    use std::task::Wake;

    /// A no-op waker implementation for testing.
    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {
            // No-op
        }

        fn wake_by_ref(self: &Arc<Self>) {
            // No-op
        }
    }

    /// Creates a no-op waker for testing.
    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }
}
