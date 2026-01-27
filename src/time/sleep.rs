//! Sleep future for delaying execution.
//!
//! The [`Sleep`] future completes after a deadline has passed.
//! It works with both wall clock time (production) and virtual time (lab).

use crate::types::Time;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

static START_TIME: OnceLock<Instant> = OnceLock::new();

#[derive(Debug)]
struct SleepState {
    waker: Option<Waker>,
    spawned: bool,
}

/// A future that completes after a specified deadline.
///
/// `Sleep` is the core primitive for time-based delays. It can be awaited
/// to pause execution until the deadline has passed.
///
/// # Time Sources
///
/// By default, `Sleep` checks time at each poll. The actual time source
/// depends on the runtime context:
/// - Production: Uses wall clock time
/// - Lab runtime: Uses virtual time
///
/// For standalone use without a runtime, you can provide a time getter.
///
/// # Cancel Safety
///
/// `Sleep` is cancel-safe. Dropping it simply stops the wait with no
/// side effects. It can be recreated with the same or a different deadline.
///
/// # Example
///
/// ```ignore
/// use asupersync::time::sleep;
/// use std::time::Duration;
///
/// // Sleep for 100 milliseconds
/// sleep(Duration::from_millis(100)).await;
///
/// // Sleep until a specific time
/// use asupersync::time::sleep_until;
/// use asupersync::types::Time;
/// sleep_until(Time::from_secs(5)).await;
/// ```
#[derive(Debug)]
pub struct Sleep {
    /// The deadline when this sleep completes.
    deadline: Time,
    /// Optional time getter for standalone use.
    /// When None, uses a default mechanism (currently instant check).
    pub(crate) time_getter: Option<fn() -> Time>,
    /// Whether this sleep has been polled at least once.
    /// Used for tracing/debugging.
    polled: Cell<bool>,
    /// Shared state for background waiter thread.
    state: Arc<Mutex<SleepState>>,
}

impl Sleep {
    /// Creates a new `Sleep` that completes at the given deadline.
    ///
    /// # Arguments
    ///
    /// * `deadline` - The absolute time when this sleep completes
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Sleep;
    /// use asupersync::types::Time;
    ///
    /// let sleep = Sleep::new(Time::from_secs(5));
    /// assert_eq!(sleep.deadline(), Time::from_secs(5));
    /// ```
    #[must_use]
    pub fn new(deadline: Time) -> Self {
        Self {
            deadline,
            time_getter: None,
            polled: Cell::new(false),
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                spawned: false,
            })),
        }
    }

    /// Creates a `Sleep` that completes after the given duration from `now`.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `duration` - How long to sleep
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Sleep;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let now = Time::from_secs(10);
    /// let sleep = Sleep::after(now, Duration::from_secs(5));
    /// assert_eq!(sleep.deadline(), Time::from_secs(15));
    /// ```
    #[must_use]
    pub fn after(now: Time, duration: Duration) -> Self {
        let deadline = now.saturating_add_nanos(duration.as_nanos() as u64);
        Self::new(deadline)
    }

    /// Creates a `Sleep` with a custom time getter function.
    ///
    /// This is useful for testing or when you need to control the time source.
    ///
    /// # Arguments
    ///
    /// * `deadline` - The deadline when this sleep completes
    /// * `time_getter` - Function that returns the current time
    #[must_use]
    pub fn with_time_getter(deadline: Time, time_getter: fn() -> Time) -> Self {
        Self {
            deadline,
            time_getter: Some(time_getter),
            polled: Cell::new(false),
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                spawned: false,
            })),
        }
    }

    /// Returns the deadline for this sleep.
    #[must_use]
    pub const fn deadline(&self) -> Time {
        self.deadline
    }

    /// Returns the remaining duration until the deadline.
    ///
    /// Returns `Duration::ZERO` if the deadline has passed.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time to compare against
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        if now >= self.deadline {
            Duration::ZERO
        } else {
            let nanos = self.deadline.as_nanos().saturating_sub(now.as_nanos());
            Duration::from_nanos(nanos)
        }
    }

    /// Checks if the deadline has elapsed.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time to compare against
    #[must_use]
    pub fn is_elapsed(&self, now: Time) -> bool {
        now >= self.deadline
    }

    /// Resets this sleep to a new deadline.
    ///
    /// This can be used to reuse a `Sleep` instance without allocating a new one.
    pub fn reset(&mut self, deadline: Time) {
        self.deadline = deadline;
        self.polled.set(false);
        let mut state = self.state.lock().expect("sleep state lock poisoned");
        state.spawned = false;
    }

    /// Resets this sleep to complete after the given duration from `now`.
    pub fn reset_after(&mut self, now: Time, duration: Duration) {
        self.deadline = now.saturating_add_nanos(duration.as_nanos() as u64);
        self.polled.set(false);
        let mut state = self.state.lock().expect("sleep state lock poisoned");
        state.spawned = false;
    }

    /// Returns true if this sleep has been polled at least once.
    #[must_use]
    pub fn was_polled(&self) -> bool {
        self.polled.get()
    }

    /// Gets the current time using the configured time getter or default.
    fn current_time(&self) -> Time {
        self.time_getter.map_or_else(
            || {
                // Production: Use wall clock
                let start = START_TIME.get_or_init(Instant::now);
                let now = Instant::now();
                if now < *start {
                    Time::ZERO
                } else {
                    let elapsed = now.duration_since(*start);
                    Time::from_nanos(elapsed.as_nanos() as u64)
                }
            },
            |getter| getter(),
        )
    }

    /// Polls this sleep with an explicit time value.
    ///
    /// This is useful when you want to control the time source manually
    /// rather than using the built-in time getter.
    ///
    /// Returns `Poll::Ready(())` if the deadline has passed.
    pub fn poll_with_time(&self, now: Time) -> Poll<()> {
        self.polled.set(true);
        if now >= self.deadline {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let now = self.current_time();
        match self.poll_with_time(now) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => {
                // If we are pending and have no time getter (using wall clock),
                // spawn a background waiter to wake us up.
                // This ensures we don't hang in a runtime without a timer driver.
                if self.time_getter.is_none() {
                    let mut state = self.state.lock().expect("sleep state lock poisoned");
                    state.waker = Some(cx.waker().clone());

                    if !state.spawned {
                        state.spawned = true;
                        let duration = self.remaining(now);
                        let state_clone = Arc::clone(&self.state);
                        drop(state);

                        std::thread::spawn(move || {
                            std::thread::sleep(duration);
                            let mut state = state_clone.lock().expect("sleep state lock poisoned");
                            if let Some(waker) = state.waker.take() {
                                waker.wake();
                            }
                            // Reset spawned flag so if we are still pending (rare), we spawn again
                            state.spawned = false;
                        });
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl Clone for Sleep {
    fn clone(&self) -> Self {
        Self {
            deadline: self.deadline,
            time_getter: self.time_getter,
            polled: Cell::new(false), // Fresh clone hasn't been polled
            state: Arc::new(Mutex::new(SleepState {
                waker: None,
                spawned: false,
            })),
        }
    }
}

/// Creates a `Sleep` future that completes after the given duration.
///
/// This function requires a current time to compute the deadline.
/// For use without explicit time, see [`sleep_until`].
///
/// # Arguments
///
/// * `now` - The current time
/// * `duration` - How long to sleep
///
/// # Example
///
/// ```
/// use asupersync::time::sleep;
/// use asupersync::types::Time;
/// use std::time::Duration;
///
/// let now = Time::from_secs(10);
/// let sleep_future = sleep(now, Duration::from_millis(100));
/// assert_eq!(sleep_future.deadline(), Time::from_nanos(10_100_000_000));
/// ```
#[must_use]
pub fn sleep(now: Time, duration: Duration) -> Sleep {
    Sleep::after(now, duration)
}

/// Creates a `Sleep` future that completes at the given deadline.
///
/// # Arguments
///
/// * `deadline` - The absolute time when the sleep completes
///
/// # Example
///
/// ```
/// use asupersync::time::sleep_until;
/// use asupersync::types::Time;
///
/// let sleep_future = sleep_until(Time::from_secs(5));
/// assert_eq!(sleep_future.deadline(), Time::from_secs(5));
/// ```
#[must_use]
pub fn sleep_until(deadline: Time) -> Sleep {
    Sleep::new(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::sync::atomic::{AtomicU64, Ordering};

    // =========================================================================
    // Construction Tests
    // =========================================================================

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    static CURRENT_TIME: AtomicU64 = AtomicU64::new(0);

    fn get_time() -> Time {
        Time::from_nanos(CURRENT_TIME.load(Ordering::SeqCst))
    }

    #[test]
    fn new_creates_sleep_with_deadline() {
        init_test("new_creates_sleep_with_deadline");
        let sleep = Sleep::new(Time::from_secs(5));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            sleep.deadline()
        );
        crate::assert_with_log!(!sleep.was_polled(), "not polled", false, sleep.was_polled());
        crate::test_complete!("new_creates_sleep_with_deadline");
    }

    #[test]
    fn after_computes_deadline() {
        init_test("after_computes_deadline");
        let now = Time::from_secs(10);
        let sleep = Sleep::after(now, Duration::from_secs(5));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(15),
            "deadline",
            Time::from_secs(15),
            sleep.deadline()
        );
        crate::test_complete!("after_computes_deadline");
    }

    #[test]
    fn after_saturates() {
        init_test("after_saturates");
        let now = Time::from_nanos(u64::MAX - 1000);
        let sleep = Sleep::after(now, Duration::from_secs(1));
        crate::assert_with_log!(
            sleep.deadline() == Time::MAX,
            "deadline",
            Time::MAX,
            sleep.deadline()
        );
        crate::test_complete!("after_saturates");
    }

    #[test]
    fn sleep_function() {
        init_test("sleep_function");
        let now = Time::from_millis(100);
        let s = sleep(now, Duration::from_millis(50));
        crate::assert_with_log!(
            s.deadline() == Time::from_millis(150),
            "deadline",
            Time::from_millis(150),
            s.deadline()
        );
        crate::test_complete!("sleep_function");
    }

    #[test]
    fn sleep_until_function() {
        init_test("sleep_until_function");
        let s = sleep_until(Time::from_secs(42));
        crate::assert_with_log!(
            s.deadline() == Time::from_secs(42),
            "deadline",
            Time::from_secs(42),
            s.deadline()
        );
        crate::test_complete!("sleep_until_function");
    }

    // =========================================================================
    // Time Getter Tests
    // =========================================================================

    #[test]
    fn with_time_getter() {
        init_test("with_time_getter");

        let sleep = Sleep::with_time_getter(Time::from_secs(5), get_time);

        // Time is 0, should be pending
        let elapsed = sleep.is_elapsed(get_time());
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);

        // Advance time past deadline
        CURRENT_TIME.store(6_000_000_000, Ordering::SeqCst);
        let elapsed = sleep.is_elapsed(get_time());
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("with_time_getter");
    }

    // =========================================================================
    // is_elapsed and remaining Tests
    // =========================================================================

    #[test]
    fn is_elapsed_before_deadline() {
        init_test("is_elapsed_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(5));
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);
        crate::test_complete!("is_elapsed_before_deadline");
    }

    #[test]
    fn is_elapsed_at_deadline() {
        init_test("is_elapsed_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(10));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("is_elapsed_at_deadline");
    }

    #[test]
    fn is_elapsed_after_deadline() {
        init_test("is_elapsed_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(15));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("is_elapsed_after_deadline");
    }

    #[test]
    fn remaining_before_deadline() {
        init_test("remaining_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(7));
        crate::assert_with_log!(
            remaining == Duration::from_secs(3),
            "remaining",
            Duration::from_secs(3),
            remaining
        );
        crate::test_complete!("remaining_before_deadline");
    }

    #[test]
    fn remaining_at_deadline() {
        init_test("remaining_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(10));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_at_deadline");
    }

    #[test]
    fn remaining_after_deadline() {
        init_test("remaining_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(15));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_after_deadline");
    }

    // =========================================================================
    // poll_with_time Tests
    // =========================================================================

    #[test]
    fn poll_with_time_before_deadline() {
        init_test("poll_with_time_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());
        crate::test_complete!("poll_with_time_before_deadline");
    }

    #[test]
    fn poll_with_time_at_deadline() {
        init_test("poll_with_time_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_at_deadline");
    }

    #[test]
    fn poll_with_time_after_deadline() {
        init_test("poll_with_time_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(15));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_after_deadline");
    }

    #[test]
    fn poll_with_time_zero_deadline() {
        init_test("poll_with_time_zero_deadline");
        let sleep = Sleep::new(Time::ZERO);
        let poll = sleep.poll_with_time(Time::ZERO);
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_zero_deadline");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_changes_deadline() {
        init_test("reset_changes_deadline");
        let mut sleep = Sleep::new(Time::from_secs(10));

        // Poll it
        let _ = sleep.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());

        // Reset
        sleep.reset(Time::from_secs(20));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(20),
            "deadline",
            Time::from_secs(20),
            sleep.deadline()
        );
        crate::assert_with_log!(
            !sleep.was_polled(),
            "reset clears polled",
            false,
            sleep.was_polled()
        ); // Reset clears polled flag
        crate::test_complete!("reset_changes_deadline");
    }

    #[test]
    fn reset_after_changes_deadline() {
        init_test("reset_after_changes_deadline");
        let mut sleep = Sleep::new(Time::from_secs(10));
        sleep.reset_after(Time::from_secs(5), Duration::from_secs(3));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(8),
            "deadline",
            Time::from_secs(8),
            sleep.deadline()
        );
        crate::test_complete!("reset_after_changes_deadline");
    }

    // =========================================================================
    // Clone Tests
    // =========================================================================

    #[test]
    fn clone_copies_deadline() {
        init_test("clone_copies_deadline");
        let original = Sleep::new(Time::from_secs(10));
        let cloned = original.clone();
        crate::assert_with_log!(
            original.deadline() == Time::from_secs(10),
            "original deadline",
            Time::from_secs(10),
            original.deadline()
        );
        crate::assert_with_log!(
            cloned.deadline() == Time::from_secs(10),
            "cloned deadline",
            Time::from_secs(10),
            cloned.deadline()
        );
        crate::test_complete!("clone_copies_deadline");
    }

    #[test]
    fn clone_has_fresh_polled_flag() {
        init_test("clone_has_fresh_polled_flag");
        let original = Sleep::new(Time::from_secs(10));
        let _ = original.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(
            original.was_polled(),
            "original polled",
            true,
            original.was_polled()
        );

        let cloned = original.clone();
        crate::assert_with_log!(
            original.was_polled(),
            "original still polled",
            true,
            original.was_polled()
        );
        crate::assert_with_log!(
            !cloned.was_polled(),
            "cloned not polled",
            false,
            cloned.was_polled()
        );
        crate::test_complete!("clone_has_fresh_polled_flag");
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn zero_duration_sleep() {
        init_test("zero_duration_sleep");
        let now = Time::from_secs(10);
        let sleep = sleep(now, Duration::ZERO);
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            sleep.deadline()
        );

        // Should be immediately ready
        let poll = sleep.poll_with_time(now);
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("zero_duration_sleep");
    }

    #[test]
    fn max_time_deadline() {
        init_test("max_time_deadline");
        let sleep = Sleep::new(Time::MAX);
        let poll = sleep.poll_with_time(Time::from_secs(1000));
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());

        // Only ready at MAX
        let poll = sleep.poll_with_time(Time::MAX);
        crate::assert_with_log!(poll.is_ready(), "ready at max", true, poll.is_ready());
        crate::test_complete!("max_time_deadline");
    }

    #[test]
    fn time_zero_deadline() {
        init_test("time_zero_deadline");
        let sleep = Sleep::new(Time::ZERO);

        // Any non-zero time is past deadline
        let poll = sleep.poll_with_time(Time::from_nanos(1));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("time_zero_deadline");
    }
}
