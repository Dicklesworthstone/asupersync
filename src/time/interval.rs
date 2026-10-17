//! Interval timer for repeating time-based operations.
//!
//! An [`Interval`] yields at a fixed period, useful for periodic tasks like
//! heartbeats, rate limiting, and polling operations.
//!
//! # Missed Tick Behavior
//!
//! When the interval cannot keep up (e.g., processing takes longer than the
//! period), the [`MissedTickBehavior`] determines how to handle missed ticks:
//!
//! - [`Burst`](MissedTickBehavior::Burst): Fire immediately for each missed tick (catch up)
//! - [`Delay`](MissedTickBehavior::Delay): Reset the timer after each tick
//! - [`Skip`](MissedTickBehavior::Skip): Skip to the next aligned tick time
//!
//! # Cancel Safety
//!
//! The `tick()` method is cancel-safe. If cancelled, the next call to `tick()`
//! will return the next scheduled tick as if nothing happened.
//!
//! # Example
//!
//! ```
//! use asupersync::time::{interval, MissedTickBehavior};
//! use asupersync::types::Time;
//! use std::time::Duration;
//!
//! let now = Time::ZERO;
//! let mut interval = interval(now, Duration::from_millis(100));
//!
//! // First tick is immediate
//! let t1 = interval.tick(now);
//! assert_eq!(t1, Time::ZERO);
//!
//! // Subsequent ticks are periodic
//! let t2 = interval.tick(Time::from_millis(100));
//! assert_eq!(t2, Time::from_millis(100));
//! ```

use crate::types::Time;
use std::time::Duration;

#[inline]
fn duration_as_nanos_u64_saturating(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Behavior for handling missed ticks in an [`Interval`].
///
/// When an interval cannot keep up with its period (e.g., because processing
/// takes longer than the interval), this enum determines how to handle the
/// missed ticks.
///
/// # Example
///
/// ```
/// use asupersync::time::MissedTickBehavior;
///
/// // Default is Burst (catch up)
/// let behavior = MissedTickBehavior::default();
/// assert_eq!(behavior, MissedTickBehavior::Burst);
///
/// // Use Delay to always wait full period from last tick
/// let behavior = MissedTickBehavior::delay();
/// assert_eq!(behavior, MissedTickBehavior::Delay);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MissedTickBehavior {
    /// Fire immediately for each missed tick (catch up).
    ///
    /// This is the default behavior. If multiple ticks were missed, `tick()`
    /// will return immediately for each one until caught up.
    ///
    /// Use this when every tick must be processed, even if delayed.
    #[default]
    Burst,

    /// Delay the next tick to be a full period from now.
    ///
    /// If a tick is missed, the next tick will be scheduled `period` after
    /// the current time, effectively resetting the interval.
    ///
    /// Use this when regular spacing matters more than total tick count.
    Delay,

    /// Skip missed ticks and fire at the next aligned time.
    ///
    /// If multiple ticks were missed, skip to the next tick that would
    /// have occurred at a multiple of `period` from the start time.
    ///
    /// Use this when ticks should align to absolute times.
    Skip,
}

impl MissedTickBehavior {
    /// Returns `Burst` behavior (fire all missed ticks).
    #[must_use]
    pub const fn burst() -> Self {
        Self::Burst
    }

    /// Returns `Delay` behavior (reset timer after each tick).
    #[must_use]
    pub const fn delay() -> Self {
        Self::Delay
    }

    /// Returns `Skip` behavior (skip to next aligned time).
    #[must_use]
    pub const fn skip() -> Self {
        Self::Skip
    }
}

impl std::fmt::Display for MissedTickBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Burst => write!(f, "Burst"),
            Self::Delay => write!(f, "Delay"),
            Self::Skip => write!(f, "Skip"),
        }
    }
}

/// A repeating interval timer.
///
/// `Interval` yields at a fixed period. Each call to [`tick`](Self::tick)
/// returns the deadline for that tick and advances to the next one.
///
/// The first tick is always at the start time (usually "now").
///
/// # Missed Tick Handling
///
/// When time advances past multiple tick deadlines before `tick()` is called,
/// the [`MissedTickBehavior`] determines how to catch up. See its documentation
/// for details on each mode.
///
/// # Example
///
/// ```
/// use asupersync::time::{Interval, MissedTickBehavior};
/// use asupersync::types::Time;
/// use std::time::Duration;
///
/// let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
///
/// // First tick at start time
/// let t1 = interval.tick(Time::ZERO);
/// assert_eq!(t1, Time::ZERO);
///
/// // Second tick at start + period
/// let t2 = interval.tick(Time::from_millis(100));
/// assert_eq!(t2, Time::from_millis(100));
/// ```
#[derive(Debug, Clone)]
pub struct Interval {
    /// The next tick deadline.
    deadline: Time,
    /// The period between ticks.
    period: Duration,
    /// Behavior for missed ticks.
    missed_tick_behavior: MissedTickBehavior,
    /// Set once the tick at `Time::MAX` has fired: no later deadline exists,
    /// so the interval stays silent until it is reset.
    exhausted: bool,
}

impl Interval {
    /// Creates a new interval timer starting at the given time.
    ///
    /// The first call to `tick()` will return `start`.
    ///
    /// # Panics
    ///
    /// Panics if `period` is zero.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Interval;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let interval = Interval::new(Time::from_secs(5), Duration::from_millis(100));
    /// assert_eq!(interval.period(), Duration::from_millis(100));
    /// ```
    #[must_use]
    pub fn new(start: Time, period: Duration) -> Self {
        assert!(!period.is_zero(), "interval period must be non-zero");
        Self {
            deadline: start,
            period,
            missed_tick_behavior: MissedTickBehavior::default(),
            exhausted: false,
        }
    }

    /// Returns the period between ticks.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the next tick deadline.
    #[must_use]
    pub const fn deadline(&self) -> Time {
        self.deadline
    }

    /// Returns the current missed tick behavior.
    #[must_use]
    pub const fn missed_tick_behavior(&self) -> MissedTickBehavior {
        self.missed_tick_behavior
    }

    /// Sets the missed tick behavior.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::{Interval, MissedTickBehavior};
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
    /// interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    /// assert_eq!(interval.missed_tick_behavior(), MissedTickBehavior::Skip);
    /// ```
    pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        self.missed_tick_behavior = behavior;
    }

    /// Waits for and returns the next tick.
    ///
    /// This is a polling-based tick that requires the current time to be passed in.
    /// If `now` is past the deadline, the tick is returned immediately and the
    /// deadline is advanced according to the missed tick behavior.
    ///
    /// If `now` is before the deadline, this returns `None` (caller should wait).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Interval;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
    ///
    /// // Time 0: first tick fires
    /// let tick = interval.tick(Time::ZERO);
    /// assert_eq!(tick, Time::ZERO);
    ///
    /// // Time 50ms: too early for next tick
    /// let tick = interval.poll_tick(Time::from_millis(50));
    /// assert_eq!(tick, None);
    ///
    /// // Time 100ms: second tick fires
    /// let tick = interval.tick(Time::from_millis(100));
    /// assert_eq!(tick, Time::from_millis(100));
    /// ```
    pub fn poll_tick(&mut self, now: Time) -> Option<Time> {
        if !self.exhausted && now >= self.deadline {
            let tick_time = self.deadline;
            self.advance_deadline(now);
            Some(tick_time)
        } else {
            None
        }
    }

    /// Returns the next tick, advancing the deadline.
    ///
    /// This is the main method for using the interval. It returns the current
    /// tick deadline if `now >= deadline`, then advances to the next deadline.
    ///
    /// Unlike `poll_tick`, this always returns a tick time (assuming `now >= deadline`).
    /// If you need to check whether a tick is ready without blocking, use `poll_tick`.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Interval;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let mut interval = Interval::new(Time::ZERO, Duration::from_secs(1));
    ///
    /// // Each tick advances by period
    /// assert_eq!(interval.tick(Time::ZERO), Time::ZERO);
    /// assert_eq!(interval.tick(Time::from_secs(1)), Time::from_secs(1));
    /// assert_eq!(interval.tick(Time::from_secs(2)), Time::from_secs(2));
    /// ```
    pub fn tick(&mut self, now: Time) -> Time {
        // If we're called before the deadline, just return the deadline without advancing.
        // This prevents consuming the tick prematurely or calculating incorrect delays.
        if self.exhausted || now < self.deadline {
            return self.deadline;
        }

        let tick_time = self.deadline;
        self.advance_deadline(now);
        tick_time
    }

    /// Returns the remaining time until the next tick.
    ///
    /// Returns `Duration::ZERO` if the deadline has passed.
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        if now >= self.deadline {
            Duration::ZERO
        } else {
            let nanos = self.deadline.as_nanos().saturating_sub(now.as_nanos());
            Duration::from_nanos(nanos)
        }
    }

    /// Checks if a tick is ready (deadline has passed).
    #[must_use]
    pub fn is_ready(&self, now: Time) -> bool {
        now >= self.deadline
    }

    /// Resets the interval to start from `now`.
    ///
    /// The next tick will be at `now`, and subsequent ticks at `now + period`,
    /// `now + 2*period`, etc.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Interval;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
    ///
    /// // Skip ahead and reset
    /// interval.reset(Time::from_secs(10));
    /// assert_eq!(interval.deadline(), Time::from_secs(10));
    /// ```
    pub fn reset(&mut self, now: Time) {
        self.deadline = now;
        self.exhausted = false;
    }

    /// Resets the interval to start at a specific time.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Interval;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
    /// interval.reset_at(Time::from_secs(5));
    /// assert_eq!(interval.deadline(), Time::from_secs(5));
    /// ```
    pub fn reset_at(&mut self, instant: Time) {
        self.deadline = instant;
        self.exhausted = false;
    }

    /// Resets the interval to fire after a delay from now.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::Interval;
    /// use asupersync::types::Time;
    /// use std::time::Duration;
    ///
    /// let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
    /// interval.reset_after(Time::from_secs(5), Duration::from_millis(500));
    /// assert_eq!(interval.deadline(), Time::from_millis(5500));
    /// ```
    pub fn reset_after(&mut self, now: Time, after: Duration) {
        self.deadline = now.saturating_add_nanos(duration_as_nanos_u64_saturating(after));
        self.exhausted = false;
    }

    /// Advances the deadline according to the missed tick behavior.
    fn advance_deadline(&mut self, now: Time) {
        // A tick at Time::MAX is the last one; every later deadline would
        // saturate back to Time::MAX and fire again forever.
        if self.deadline == Time::MAX {
            self.exhausted = true;
            return;
        }
        let period_nanos = duration_as_nanos_u64_saturating(self.period);

        match self.missed_tick_behavior {
            MissedTickBehavior::Burst => {
                // Just add one period (caller handles bursting by calling tick repeatedly)
                self.deadline = self.deadline.saturating_add_nanos(period_nanos);
            }
            MissedTickBehavior::Delay => {
                // Next tick is period from now
                self.deadline = now.saturating_add_nanos(period_nanos);
            }
            MissedTickBehavior::Skip => {
                // Skip to next aligned tick
                if now >= self.deadline {
                    let elapsed = now.as_nanos() - self.deadline.as_nanos();
                    let periods_to_skip = elapsed / period_nanos;
                    // Only add 1 to periods_to_skip. We want the next deadline to be strictly > now.
                    // Since elapsed = now - deadline, deadline + periods_to_skip * period_nanos <= now.
                    // By adding 1, the new deadline is > now.
                    let periods_to_skip = periods_to_skip.saturating_add(1);
                    let skipped_nanos = periods_to_skip.saturating_mul(period_nanos);
                    self.deadline = self.deadline.saturating_add_nanos(skipped_nanos);
                } else {
                    self.deadline = self.deadline.saturating_add_nanos(period_nanos);
                }
            }
        }
    }
}

/// Creates an interval that yields at the given period, starting from `now`.
///
/// The first tick is immediate (at `now`).
///
/// # Panics
///
/// Panics if `period` is zero.
///
/// # Example
///
/// ```
/// use asupersync::time::interval;
/// use asupersync::types::Time;
/// use std::time::Duration;
///
/// let now = Time::ZERO;
/// let mut int = interval(now, Duration::from_millis(100));
///
/// assert_eq!(int.tick(now), Time::ZERO);
/// assert_eq!(int.tick(Time::from_millis(100)), Time::from_millis(100));
/// ```
#[must_use]
pub fn interval(now: Time, period: Duration) -> Interval {
    Interval::new(now, period)
}

/// Creates an interval that yields at the given period, starting from `start`.
///
/// Unlike [`interval`], this allows specifying a start time different from now.
///
/// # Panics
///
/// Panics if `period` is zero.
///
/// # Example
///
/// ```
/// use asupersync::time::interval_at;
/// use asupersync::types::Time;
/// use std::time::Duration;
///
/// // Start 1 second in the future
/// let start = Time::from_secs(1);
/// let mut int = interval_at(start, Duration::from_millis(100));
///
/// // First tick at start time
/// assert_eq!(int.tick(start), Time::from_secs(1));
/// ```
#[must_use]
pub fn interval_at(start: Time, period: Duration) -> Interval {
    Interval::new(start, period)
}

#[cfg(test)]
#[path = "interval_inline_tests.rs"]
mod tests;
