//! Timer driver for managing sleep/timeout registration.
//!
//! The timer driver provides the time source and manages timer registrations
//! using a hierarchical timing wheel. It supports both production (wall clock)
//! and virtual (lab) time.

use crate::types::Time;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Waker;
use std::time::Duration;

use super::wheel::{TimerWheel, WakerBatch};

#[inline]
fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Time source abstraction for getting the current time.
///
/// This trait allows the timer driver to work with both wall clock time
/// (production) and virtual time (lab testing).
pub trait TimeSource: Send + Sync {
    /// Returns the current time.
    fn now(&self) -> Time;
}

/// Wall clock time source for production use.
///
/// Uses `std::time::Instant` internally, converting to our `Time` type.
/// The epoch is the time when this source was created.
#[derive(Debug)]
pub struct WallClock {
    /// The instant when this clock was created.
    epoch: std::time::Instant,
}

impl WallClock {
    /// Creates a new wall clock time source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for WallClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for WallClock {
    fn now(&self) -> Time {
        let elapsed = self.epoch.elapsed();
        Time::from_nanos(duration_to_nanos_saturating(elapsed))
    }
}

/// Browser-oriented monotonic clock configuration.
///
/// The browser clock adapter ingests host time samples (for example
/// `performance.now()`) and maps them onto Asupersync `Time` while:
///
/// - preserving monotonicity even if host samples regress,
/// - smoothing tiny jitter via a minimum-step floor, and
/// - bounding large catch-up jumps (for background-tab throttling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserClockConfig {
    /// Maximum monotonic advancement applied per host sample.
    ///
    /// Set to `Duration::ZERO` to disable capping and apply full deltas.
    pub max_forward_step: Duration,
    /// Minimum delta applied immediately; smaller deltas are accumulated.
    pub jitter_floor: Duration,
}

impl Default for BrowserClockConfig {
    fn default() -> Self {
        Self {
            max_forward_step: Duration::from_millis(250),
            jitter_floor: Duration::from_millis(1),
        }
    }
}

/// Browser monotonic clock built from host time samples.
///
/// This clock is intended for browser scheduler/timer adapters. Call
/// [`observe_host_time`](Self::observe_host_time) from host callbacks to feed
/// new host samples into the clock.
///
/// Suspension mitigation:
/// - call [`suspend`](Self::suspend) when the tab/page is hidden,
/// - call [`resume`](Self::resume) when visible again (first sample rebases).
#[derive(Debug)]
pub struct BrowserMonotonicClock {
    now: AtomicU64,
    paused: AtomicBool,
    paused_at: AtomicU64,
    has_host_sample: AtomicBool,
    last_host_sample: AtomicU64,
    pending_catch_up_ns: AtomicU64,
    max_forward_step_ns: u64,
    jitter_floor_ns: u64,
}

impl BrowserMonotonicClock {
    /// Creates a browser monotonic clock with explicit policy.
    #[must_use]
    pub fn new(config: BrowserClockConfig) -> Self {
        Self {
            now: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            paused_at: AtomicU64::new(0),
            has_host_sample: AtomicBool::new(false),
            last_host_sample: AtomicU64::new(0),
            pending_catch_up_ns: AtomicU64::new(0),
            max_forward_step_ns: duration_to_nanos_saturating(config.max_forward_step),
            jitter_floor_ns: duration_to_nanos_saturating(config.jitter_floor),
        }
    }

    /// Ingests a host-time sample and updates monotonic time.
    ///
    /// The first sample only establishes a host baseline and does not advance
    /// runtime time.
    pub fn observe_host_time(&self, host: Duration) -> Time {
        let host_ns = duration_to_nanos_saturating(host);
        self.observe_host_nanos(host_ns)
    }

    /// Ingests a host-time sample in nanoseconds.
    pub fn observe_host_nanos(&self, host_ns: u64) -> Time {
        if self.paused.load(Ordering::Acquire) {
            return Time::from_nanos(self.paused_at.load(Ordering::Acquire));
        }

        // Rebase on first sample (or first sample after resume) without jump.
        if self
            .has_host_sample
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.last_host_sample.store(host_ns, Ordering::Release);
            return self.now();
        }

        // Clamp regressions by tracking the max host sample seen.
        let previous_host = self.last_host_sample.fetch_max(host_ns, Ordering::AcqRel);
        let host_delta = host_ns.saturating_sub(previous_host);
        let combined_delta =
            host_delta.saturating_add(self.pending_catch_up_ns.load(Ordering::Acquire));

        if combined_delta < self.jitter_floor_ns {
            self.pending_catch_up_ns
                .store(combined_delta, Ordering::Release);
            return self.now();
        }

        let applied = if self.max_forward_step_ns == 0 {
            combined_delta
        } else {
            combined_delta.min(self.max_forward_step_ns)
        };
        self.pending_catch_up_ns
            .store(combined_delta.saturating_sub(applied), Ordering::Release);
        self.advance_now(applied)
    }

    /// Freezes clock advancement while hidden/throttled.
    pub fn suspend(&self) {
        let now = self.now.load(Ordering::Acquire);
        self.paused_at.store(now, Ordering::Release);
        self.paused.store(true, Ordering::Release);
    }

    /// Resumes clock advancement.
    ///
    /// Resuming clears host baseline and pending catch-up so the next host
    /// sample rebases instead of producing a giant jump.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        self.has_host_sample.store(false, Ordering::Release);
        self.pending_catch_up_ns.store(0, Ordering::Release);
    }

    /// Returns true when the browser clock is suspended.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// Returns pending deferred advancement.
    #[must_use]
    pub fn pending_catch_up(&self) -> Duration {
        Duration::from_nanos(self.pending_catch_up_ns.load(Ordering::Acquire))
    }

    fn advance_now(&self, delta: u64) -> Time {
        if delta == 0 {
            return self.now();
        }

        let mut current = self.now.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(delta);
            match self
                .now
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Time::from_nanos(next),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Default for BrowserMonotonicClock {
    fn default() -> Self {
        Self::new(BrowserClockConfig::default())
    }
}

impl TimeSource for BrowserMonotonicClock {
    fn now(&self) -> Time {
        if self.paused.load(Ordering::Acquire) {
            Time::from_nanos(self.paused_at.load(Ordering::Acquire))
        } else {
            Time::from_nanos(self.now.load(Ordering::Acquire))
        }
    }
}

/// Virtual time source for lab testing.
///
/// Time only advances when explicitly told to do so, enabling
/// deterministic testing of time-dependent code.
///
/// # Example
///
/// ```
/// use asupersync::time::{TimeSource, VirtualClock};
/// use asupersync::types::Time;
///
/// let clock = VirtualClock::new();
/// assert_eq!(clock.now(), Time::ZERO);
///
/// clock.advance(1_000_000_000); // 1 second
/// assert_eq!(clock.now(), Time::from_secs(1));
/// ```
#[derive(Debug)]
pub struct VirtualClock {
    /// Current time in nanoseconds.
    now: AtomicU64,
    /// When true, `now()` returns the frozen time and `advance`/`advance_to`
    /// are no-ops. The frozen time is captured at the moment `pause()` is called.
    paused: AtomicBool,
    /// Frozen time snapshot captured when the clock is paused.
    frozen_at: AtomicU64,
}

impl VirtualClock {
    /// Creates a new virtual clock starting at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            frozen_at: AtomicU64::new(0),
        }
    }

    /// Creates a virtual clock starting at the given time.
    #[must_use]
    pub fn starting_at(time: Time) -> Self {
        Self {
            now: AtomicU64::new(time.as_nanos()),
            paused: AtomicBool::new(false),
            frozen_at: AtomicU64::new(time.as_nanos()),
        }
    }

    /// Advances time by the given number of nanoseconds.
    ///
    /// No-op when the clock is paused.
    pub fn advance(&self, nanos: u64) {
        if !self.paused.load(Ordering::Acquire) {
            self.now.fetch_add(nanos, Ordering::Release);
        }
    }

    /// Advances time to the given absolute time.
    ///
    /// If the target time is in the past, or the clock is paused, this is a no-op.
    pub fn advance_to(&self, time: Time) {
        if self.paused.load(Ordering::Acquire) {
            return;
        }
        let target = time.as_nanos();
        let mut current = self.now.load(Ordering::Acquire);
        while current < target {
            match self.now.compare_exchange_weak(
                current,
                target,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Sets the current time (for testing).
    pub fn set(&self, time: Time) {
        self.now.store(time.as_nanos(), Ordering::Release);
    }

    /// Pauses the clock, freezing `now()` at the current time.
    ///
    /// While paused, `advance()` and `advance_to()` are no-ops.
    /// Call `resume()` to unfreeze.
    pub fn pause(&self) {
        let current = self.now.load(Ordering::Acquire);
        self.frozen_at.store(current, Ordering::Release);
        self.paused.store(true, Ordering::Release);
    }

    /// Resumes a paused clock.
    ///
    /// The clock continues from the time it was paused at (no jump).
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }

    /// Returns true if the clock is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for VirtualClock {
    fn now(&self) -> Time {
        if self.paused.load(Ordering::Acquire) {
            Time::from_nanos(self.frozen_at.load(Ordering::Acquire))
        } else {
            Time::from_nanos(self.now.load(Ordering::Acquire))
        }
    }
}

pub use super::wheel::TimerHandle;

/// Timer driver that manages timer registrations and fires them.
///
/// The driver maintains a hierarchical timing wheel ordered by deadline.
/// When `process_timers` is called, all expired timers have their wakers called.
///
/// # Thread Safety
///
/// The driver is thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```
/// use asupersync::time::{TimerDriver, VirtualClock};
/// use asupersync::types::Time;
/// use std::sync::Arc;
///
/// let clock = Arc::new(VirtualClock::new());
/// let driver = TimerDriver::with_clock(clock.clone());
///
/// // In a real scenario, you'd register timers via Sleep futures
/// // and process them in your event loop.
/// ```
#[derive(Debug)]
pub struct TimerDriver<T: TimeSource = VirtualClock> {
    /// The time source.
    clock: std::sync::Arc<T>,
    /// Timing wheel (protected by mutex for thread safety).
    wheel: Mutex<TimerWheel>,
}

impl<T: TimeSource> TimerDriver<T> {
    /// Creates a new timer driver with the given time source.
    #[must_use]
    pub fn with_clock(clock: std::sync::Arc<T>) -> Self {
        let now = clock.now();
        Self {
            clock,
            wheel: Mutex::new(TimerWheel::new_at(now)),
        }
    }

    /// Returns the current time from the underlying clock.
    #[must_use]
    pub fn now(&self) -> Time {
        self.clock.now()
    }

    /// Registers a timer to fire at the given deadline.
    ///
    /// Returns a handle that can be used to identify the timer.
    /// The waker will be called when `process_timers` is called
    /// and the deadline has passed.
    pub fn register(&self, deadline: Time, waker: Waker) -> TimerHandle {
        self.wheel.lock().register(deadline, waker)
    }

    /// Updates an existing timer registration with a new deadline and waker.
    ///
    /// This doesn't actually remove the old entry (to avoid O(n) removal),
    /// but registers a new one. Stale entries are cleaned up on pop.
    pub fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle {
        let mut wheel = self.wheel.lock();
        wheel.cancel(handle);
        wheel.register(deadline, waker)
    }

    /// Cancels an existing timer registration.
    ///
    /// Returns true if the timer was active and is now cancelled.
    pub fn cancel(&self, handle: &TimerHandle) -> bool {
        self.wheel.lock().cancel(handle)
    }

    /// Returns the next deadline that will fire, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Time> {
        self.wheel.lock().next_deadline()
    }

    /// Processes all expired timers, calling their wakers.
    ///
    /// Returns the number of timers fired.
    pub fn process_timers(&self) -> usize {
        let now = self.clock.now();

        // Collect expired entries while holding the lock, then release it
        // before waking to prevent potential deadlocks if wakers try to
        // re-enter the timer driver.
        let expired_wakers = self.collect_expired(now);
        let fired = expired_wakers.len();

        // Wake them outside the lock
        for waker in expired_wakers {
            waker.wake();
        }

        fired
    }

    /// Helper to collect expired wakers while holding the lock.
    #[allow(clippy::significant_drop_tightening)]
    fn collect_expired(&self, now: Time) -> WakerBatch {
        self.wheel.lock().collect_expired(now)
    }

    /// Returns the number of pending timers.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.wheel.lock().len()
    }

    /// Returns true if there are no pending timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wheel.lock().is_empty()
    }

    /// Clears all pending timers without firing them.
    pub fn clear(&self) {
        self.wheel.lock().clear();
    }
}

impl TimerDriver<VirtualClock> {
    /// Creates a new timer driver with a virtual clock.
    ///
    /// This is the default for testing and lab use.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(std::sync::Arc::new(VirtualClock::new()))
    }
}

impl Default for TimerDriver<VirtualClock> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TimerDriverHandle - Shared handle for timer driver access
// =============================================================================

/// Trait abstracting timer driver operations for use with trait objects.
///
/// This allows the runtime to create either wall-clock or virtual-clock
/// based drivers while consumers use a unified handle type.
pub trait TimerDriverApi: Send + Sync + std::fmt::Debug {
    /// Returns the current time.
    fn now(&self) -> Time;

    /// Registers a timer to fire at the given deadline.
    fn register(&self, deadline: Time, waker: Waker) -> TimerHandle;

    /// Updates an existing timer with a new deadline and waker.
    fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle;

    /// Cancels an existing timer.
    fn cancel(&self, handle: &TimerHandle) -> bool;

    /// Returns the next deadline that will fire.
    fn next_deadline(&self) -> Option<Time>;

    /// Processes expired timers, calling their wakers.
    fn process_timers(&self) -> usize;

    /// Returns the number of pending timers.
    fn pending_count(&self) -> usize;

    /// Returns true if no timers are pending.
    fn is_empty(&self) -> bool;
}

impl<T: TimeSource + std::fmt::Debug + 'static> TimerDriverApi for TimerDriver<T> {
    fn now(&self) -> Time {
        Self::now(self)
    }

    fn register(&self, deadline: Time, waker: Waker) -> TimerHandle {
        Self::register(self, deadline, waker)
    }

    fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle {
        Self::update(self, handle, deadline, waker)
    }

    fn cancel(&self, handle: &TimerHandle) -> bool {
        Self::cancel(self, handle)
    }

    fn next_deadline(&self) -> Option<Time> {
        Self::next_deadline(self)
    }

    fn process_timers(&self) -> usize {
        Self::process_timers(self)
    }

    fn pending_count(&self) -> usize {
        Self::pending_count(self)
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }
}

/// Shared handle to a timer driver.
///
/// This wrapper provides cloneable access to the runtime's timer driver
/// from async contexts. It abstracts over the concrete time source
/// (wall clock vs virtual clock) using a trait object.
///
/// # Example
///
/// ```ignore
/// use asupersync::time::TimerDriverHandle;
///
/// // Get handle from current context
/// if let Some(timer) = Cx::current().and_then(|cx| cx.timer_driver()) {
///     let deadline = timer.now() + Duration::from_secs(1);
///     let handle = timer.register(deadline, waker);
/// }
/// ```
#[derive(Clone)]
pub struct TimerDriverHandle {
    inner: Arc<dyn TimerDriverApi>,
}

impl std::fmt::Debug for TimerDriverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerDriverHandle")
            .field("pending_count", &self.inner.pending_count())
            .finish()
    }
}

impl TimerDriverHandle {
    /// Creates a new handle wrapping the given timer driver.
    #[inline]
    pub fn new<T: TimeSource + std::fmt::Debug + 'static>(driver: Arc<TimerDriver<T>>) -> Self {
        Self { inner: driver }
    }

    /// Returns true if two handles refer to the same underlying driver.
    #[inline]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Creates a handle with a wall clock timer driver for production use.
    #[must_use]
    pub fn with_wall_clock() -> Self {
        let clock = Arc::new(WallClock::new());
        let driver = Arc::new(TimerDriver::with_clock(clock));
        Self::new(driver)
    }

    /// Creates a handle with a virtual clock timer driver for testing.
    #[must_use]
    pub fn with_virtual_clock(clock: Arc<VirtualClock>) -> Self {
        let driver = Arc::new(TimerDriver::with_clock(clock));
        Self::new(driver)
    }

    /// Creates a handle with a browser-monotonic timer driver.
    #[must_use]
    pub fn with_browser_clock(clock: Arc<BrowserMonotonicClock>) -> Self {
        let driver = Arc::new(TimerDriver::with_clock(clock));
        Self::new(driver)
    }

    /// Returns the current time from the timer driver.
    #[inline]
    #[must_use]
    pub fn now(&self) -> Time {
        self.inner.now()
    }

    /// Registers a timer to fire at the given deadline.
    ///
    /// Returns a handle that can be used to cancel or update the timer.
    #[inline]
    #[must_use]
    pub fn register(&self, deadline: Time, waker: Waker) -> TimerHandle {
        self.inner.register(deadline, waker)
    }

    /// Updates an existing timer with a new deadline and waker.
    #[inline]
    #[must_use]
    pub fn update(&self, handle: &TimerHandle, deadline: Time, waker: Waker) -> TimerHandle {
        self.inner.update(handle, deadline, waker)
    }

    /// Cancels an existing timer.
    ///
    /// Returns true if the timer was active and is now cancelled.
    #[inline]
    #[must_use]
    pub fn cancel(&self, handle: &TimerHandle) -> bool {
        self.inner.cancel(handle)
    }

    /// Returns the next deadline that will fire, if any.
    #[inline]
    #[must_use]
    pub fn next_deadline(&self) -> Option<Time> {
        self.inner.next_deadline()
    }

    /// Processes all expired timers, calling their wakers.
    ///
    /// Returns the number of timers fired.
    #[inline]
    #[must_use]
    pub fn process_timers(&self) -> usize {
        self.inner.process_timers()
    }

    /// Returns the number of pending timers.
    #[inline]
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// Returns true if no timers are pending.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // =========================================================================
    // VirtualClock Tests
    // =========================================================================

    #[test]
    fn virtual_clock_starts_at_zero() {
        init_test("virtual_clock_starts_at_zero");
        let clock = VirtualClock::new();
        let now = clock.now();
        crate::assert_with_log!(now == Time::ZERO, "clock starts at zero", Time::ZERO, now);
        crate::test_complete!("virtual_clock_starts_at_zero");
    }

    #[test]
    fn virtual_clock_starting_at() {
        init_test("virtual_clock_starting_at");
        let clock = VirtualClock::starting_at(Time::from_secs(10));
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(10),
            "clock starts at 10s",
            Time::from_secs(10),
            now
        );
        crate::test_complete!("virtual_clock_starting_at");
    }

    #[test]
    fn virtual_clock_advance() {
        init_test("virtual_clock_advance");
        let clock = VirtualClock::new();
        clock.advance(1_000_000_000); // 1 second
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "advance 1s",
            Time::from_secs(1),
            now
        );

        clock.advance(500_000_000); // 0.5 seconds
        let nanos = clock.now().as_nanos();
        crate::assert_with_log!(nanos == 1_500_000_000, "advance 0.5s", 1_500_000_000, nanos);
        crate::test_complete!("virtual_clock_advance");
    }

    #[test]
    fn virtual_clock_advance_to() {
        init_test("virtual_clock_advance_to");
        let clock = VirtualClock::new();
        clock.advance_to(Time::from_secs(5));
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(5),
            "advance_to 5s",
            Time::from_secs(5),
            now
        );

        // Advancing to past time is no-op
        clock.advance_to(Time::from_secs(3));
        let now_after = clock.now();
        crate::assert_with_log!(
            now_after == Time::from_secs(5),
            "advance_to past is no-op",
            Time::from_secs(5),
            now_after
        );
        crate::test_complete!("virtual_clock_advance_to");
    }

    #[test]
    fn virtual_clock_set() {
        init_test("virtual_clock_set");
        let clock = VirtualClock::new();
        clock.set(Time::from_secs(100));
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(100),
            "set to 100s",
            Time::from_secs(100),
            now
        );

        // Set can go backwards
        clock.set(Time::from_secs(50));
        let now_back = clock.now();
        crate::assert_with_log!(
            now_back == Time::from_secs(50),
            "set backwards to 50s",
            Time::from_secs(50),
            now_back
        );
        crate::test_complete!("virtual_clock_set");
    }

    #[test]
    fn virtual_clock_pause_freezes_time() {
        init_test("virtual_clock_pause_freezes_time");
        let clock = VirtualClock::new();
        clock.advance(1_000_000_000); // 1 second
        clock.pause();

        let paused = clock.is_paused();
        crate::assert_with_log!(paused, "is_paused", true, paused);

        let frozen = clock.now();
        crate::assert_with_log!(
            frozen == Time::from_secs(1),
            "frozen at 1s",
            Time::from_secs(1),
            frozen
        );

        // Advance is a no-op while paused
        clock.advance(5_000_000_000);
        let still_frozen = clock.now();
        crate::assert_with_log!(
            still_frozen == Time::from_secs(1),
            "still frozen at 1s",
            Time::from_secs(1),
            still_frozen
        );

        // advance_to is also a no-op while paused
        clock.advance_to(Time::from_secs(100));
        let still_frozen2 = clock.now();
        crate::assert_with_log!(
            still_frozen2 == Time::from_secs(1),
            "still frozen after advance_to",
            Time::from_secs(1),
            still_frozen2
        );
        crate::test_complete!("virtual_clock_pause_freezes_time");
    }

    #[test]
    fn virtual_clock_resume_unfreezes() {
        init_test("virtual_clock_resume_unfreezes");
        let clock = VirtualClock::new();
        clock.advance(1_000_000_000);
        clock.pause();
        clock.resume();

        let resumed = !clock.is_paused();
        crate::assert_with_log!(resumed, "not paused", true, resumed);

        // Advance works again
        clock.advance(2_000_000_000);
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(3),
            "resumed and advanced",
            Time::from_secs(3),
            now
        );
        crate::test_complete!("virtual_clock_resume_unfreezes");
    }

    // =========================================================================
    // BrowserMonotonicClock Tests
    // =========================================================================

    #[test]
    fn browser_clock_first_sample_rebases_without_jump() {
        init_test("browser_clock_first_sample_rebases_without_jump");
        let clock = BrowserMonotonicClock::default();
        crate::assert_with_log!(
            clock.now() == Time::ZERO,
            "starts at zero",
            Time::ZERO,
            clock.now()
        );

        let t = clock.observe_host_time(Duration::from_millis(250));
        crate::assert_with_log!(
            t == Time::ZERO,
            "first sample is baseline only",
            Time::ZERO,
            t
        );
        crate::test_complete!("browser_clock_first_sample_rebases_without_jump");
    }

    #[test]
    fn browser_clock_clamps_regression_monotonically() {
        init_test("browser_clock_clamps_regression_monotonically");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::ZERO,
        });

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let t1 = clock.observe_host_time(Duration::from_millis(130));
        crate::assert_with_log!(
            t1 == Time::from_millis(30),
            "advances with forward host sample",
            Time::from_millis(30),
            t1
        );

        let t2 = clock.observe_host_time(Duration::from_millis(120));
        crate::assert_with_log!(
            t2 == Time::from_millis(30),
            "regressed host sample does not move clock backward",
            Time::from_millis(30),
            t2
        );

        let t3 = clock.observe_host_time(Duration::from_millis(150));
        crate::assert_with_log!(
            t3 == Time::from_millis(50),
            "clock resumes monotonic progression after regression",
            Time::from_millis(50),
            t3
        );
        crate::test_complete!("browser_clock_clamps_regression_monotonically");
    }

    #[test]
    fn browser_clock_jitter_floor_accumulates_small_deltas() {
        init_test("browser_clock_jitter_floor_accumulates_small_deltas");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::from_millis(10),
        });

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let t1 = clock.observe_host_time(Duration::from_millis(103));
        crate::assert_with_log!(t1 == Time::ZERO, "sub-floor delta deferred", Time::ZERO, t1);
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::from_millis(3),
            "pending catch-up tracks deferred jitter",
            Duration::from_millis(3),
            clock.pending_catch_up()
        );

        let t2 = clock.observe_host_time(Duration::from_millis(110));
        crate::assert_with_log!(
            t2 == Time::from_millis(10),
            "accumulated jitter released at floor",
            Time::from_millis(10),
            t2
        );
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::ZERO,
            "pending catch-up drained",
            Duration::ZERO,
            clock.pending_catch_up()
        );
        crate::test_complete!("browser_clock_jitter_floor_accumulates_small_deltas");
    }

    #[test]
    fn browser_clock_limits_catch_up_per_observation() {
        init_test("browser_clock_limits_catch_up_per_observation");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::from_millis(50),
            jitter_floor: Duration::ZERO,
        });

        let _ = clock.observe_host_time(Duration::ZERO);
        let t1 = clock.observe_host_time(Duration::from_millis(200));
        crate::assert_with_log!(
            t1 == Time::from_millis(50),
            "first catch-up slice capped",
            Time::from_millis(50),
            t1
        );
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::from_millis(150),
            "remaining catch-up retained",
            Duration::from_millis(150),
            clock.pending_catch_up()
        );

        let t2 = clock.observe_host_time(Duration::from_millis(200));
        crate::assert_with_log!(
            t2 == Time::from_millis(100),
            "second slice advances deterministically",
            Time::from_millis(100),
            t2
        );
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::from_millis(100),
            "catch-up debt decreases by cap",
            Duration::from_millis(100),
            clock.pending_catch_up()
        );
        crate::test_complete!("browser_clock_limits_catch_up_per_observation");
    }

    #[test]
    fn browser_clock_suspend_resume_rebases_without_jump() {
        init_test("browser_clock_suspend_resume_rebases_without_jump");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::ZERO,
        });

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let t1 = clock.observe_host_time(Duration::from_millis(120));
        crate::assert_with_log!(
            t1 == Time::from_millis(20),
            "advances before suspend",
            Time::from_millis(20),
            t1
        );

        clock.suspend();
        crate::assert_with_log!(
            clock.is_suspended(),
            "clock suspended",
            true,
            clock.is_suspended()
        );
        let t2 = clock.observe_host_time(Duration::from_millis(500));
        crate::assert_with_log!(
            t2 == Time::from_millis(20),
            "suspended clock does not advance",
            Time::from_millis(20),
            t2
        );

        clock.resume();
        crate::assert_with_log!(
            !clock.is_suspended(),
            "clock resumed",
            false,
            clock.is_suspended()
        );

        let t3 = clock.observe_host_time(Duration::from_millis(700));
        crate::assert_with_log!(
            t3 == Time::from_millis(20),
            "first post-resume sample rebases",
            Time::from_millis(20),
            t3
        );
        let t4 = clock.observe_host_time(Duration::from_millis(730));
        crate::assert_with_log!(
            t4 == Time::from_millis(50),
            "post-resume progression uses new baseline",
            Time::from_millis(50),
            t4
        );
        crate::test_complete!("browser_clock_suspend_resume_rebases_without_jump");
    }

    // =========================================================================
    // WallClock Tests
    // =========================================================================

    #[test]
    fn duration_to_nanos_saturates_at_u64_max() {
        init_test("duration_to_nanos_saturates_at_u64_max");
        let nanos = duration_to_nanos_saturating(Duration::MAX);
        crate::assert_with_log!(nanos == u64::MAX, "duration saturates", u64::MAX, nanos);
        crate::test_complete!("duration_to_nanos_saturates_at_u64_max");
    }

    #[test]
    fn wall_clock_starts_near_zero() {
        init_test("wall_clock_starts_near_zero");
        let clock = WallClock::new();
        let now = clock.now();
        // Should be very close to zero (within 1ms of creation)
        let max_nanos = 1_000_000;
        let actual = now.as_nanos();
        crate::assert_with_log!(actual < max_nanos, "near zero", max_nanos, actual);
        crate::test_complete!("wall_clock_starts_near_zero");
    }

    #[test]
    fn wall_clock_advances() {
        init_test("wall_clock_advances");
        let clock = WallClock::new();
        let t1 = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clock.now();
        crate::assert_with_log!(t2 > t1, "clock advances", "t2 > t1", (t1, t2));
        crate::test_complete!("wall_clock_advances");
    }

    // =========================================================================
    // TimerDriver Tests
    // =========================================================================

    #[test]
    fn timer_driver_new() {
        init_test("timer_driver_new");
        let driver = TimerDriver::new();
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::assert_with_log!(
            driver.pending_count() == 0,
            "pending count",
            0,
            driver.pending_count()
        );
        crate::test_complete!("timer_driver_new");
    }

    #[test]
    fn timer_driver_register() {
        init_test("timer_driver_register");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        let waker = futures_waker();
        let handle = driver.register(Time::from_secs(1), waker);

        crate::assert_with_log!(handle.id() == 0, "handle id", 0, handle.id());
        crate::assert_with_log!(
            driver.pending_count() == 1,
            "pending count",
            1,
            driver.pending_count()
        );
        crate::assert_with_log!(
            !driver.is_empty(),
            "driver not empty",
            false,
            driver.is_empty()
        );
        crate::test_complete!("timer_driver_register");
    }

    #[test]
    fn timer_driver_next_deadline() {
        init_test("timer_driver_next_deadline");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        let expected: Option<Time> = None;
        let actual = driver.next_deadline();
        crate::assert_with_log!(actual == expected, "empty next_deadline", expected, actual);

        driver.register(Time::from_secs(5), futures_waker());
        driver.register(Time::from_secs(3), futures_waker());
        driver.register(Time::from_secs(7), futures_waker());

        // Should return earliest deadline
        let expected = Some(Time::from_secs(3));
        let actual = driver.next_deadline();
        crate::assert_with_log!(actual == expected, "earliest deadline", expected, actual);
        crate::test_complete!("timer_driver_next_deadline");
    }

    #[test]
    fn timer_driver_process_expired() {
        init_test("timer_driver_process_expired");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let woken = Arc::new(AtomicBool::new(false));
        let woken_clone = woken.clone();

        let waker = waker_that_sets(woken_clone);
        driver.register(Time::from_secs(1), waker);

        // Time is 0, no timers should fire
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 0, "process_timers at t=0", 0, processed);
        let woken_now = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(!woken_now, "not woken", false, woken_now);

        // Advance time past deadline
        clock.advance(2_000_000_000); // 2 seconds
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 1, "process_timers after advance", 1, processed);
        let woken_now = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(woken_now, "woken", true, woken_now);

        // No more timers
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_process_expired");
    }

    #[test]
    fn timer_driver_does_not_fire_while_clock_paused() {
        init_test("timer_driver_does_not_fire_while_clock_paused");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let woken = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(woken.clone());
        driver.register(Time::from_secs(1), waker);

        clock.pause();
        clock.advance(2_000_000_000);
        let fired_while_paused = driver.process_timers();
        crate::assert_with_log!(
            fired_while_paused == 0,
            "paused clock does not advance timers",
            0,
            fired_while_paused
        );
        crate::assert_with_log!(
            !woken.load(Ordering::SeqCst),
            "waker not called while paused",
            false,
            woken.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            driver.pending_count() == 1,
            "timer remains pending while paused",
            1,
            driver.pending_count()
        );

        clock.resume();
        clock.advance(2_000_000_000);
        let fired_after_resume = driver.process_timers();
        crate::assert_with_log!(
            fired_after_resume == 1,
            "timer fires after resume and advance",
            1,
            fired_after_resume
        );
        crate::assert_with_log!(
            woken.load(Ordering::SeqCst),
            "waker called after resume",
            true,
            woken.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_does_not_fire_while_clock_paused");
    }

    #[test]
    fn timer_driver_multiple_timers() {
        init_test("timer_driver_multiple_timers");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let count = Arc::new(AtomicU64::new(0));

        for i in 1..=5 {
            let count_clone = count.clone();
            let waker = waker_that_increments(count_clone);
            driver.register(Time::from_secs(i), waker);
        }

        crate::assert_with_log!(
            driver.pending_count() == 5,
            "pending count",
            5,
            driver.pending_count()
        );

        // Advance to t=3, should fire 3 timers
        clock.set(Time::from_secs(3));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 3, "process_timers at t=3", 3, processed);
        let count_now = count.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 3, "count at t=3", 3, count_now);
        crate::assert_with_log!(
            driver.pending_count() == 2,
            "pending count after t=3",
            2,
            driver.pending_count()
        );

        // Advance to t=10, should fire remaining 2
        clock.set(Time::from_secs(10));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 2, "process_timers at t=10", 2, processed);
        let count_now = count.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 5, "count at t=10", 5, count_now);
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_multiple_timers");
    }

    #[test]
    fn timer_driver_update_cancels_old_handle() {
        init_test("timer_driver_update_cancels_old_handle");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let counter = Arc::new(AtomicU64::new(0));
        let waker = waker_that_increments(counter.clone());
        let handle = driver.register(Time::from_secs(5), waker);

        let waker2 = waker_that_increments(counter.clone());
        let _new_handle = driver.update(&handle, Time::from_secs(2), waker2);

        clock.set(Time::from_secs(3));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 1, "process_timers at t=3", 1, processed);
        let count_now = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 1, "counter", 1, count_now);

        clock.set(Time::from_secs(10));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 0, "process_timers at t=10", 0, processed);
        let count_now = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 1, "counter stable", 1, count_now);
        crate::test_complete!("timer_driver_update_cancels_old_handle");
    }

    #[test]
    fn timer_driver_clear() {
        init_test("timer_driver_clear");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        driver.register(Time::from_secs(1), futures_waker());
        driver.register(Time::from_secs(2), futures_waker());

        crate::assert_with_log!(
            driver.pending_count() == 2,
            "pending count",
            2,
            driver.pending_count()
        );
        driver.clear();
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_clear");
    }

    #[test]
    fn timer_driver_now() {
        init_test("timer_driver_now");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let now = driver.now();
        crate::assert_with_log!(now == Time::ZERO, "now at zero", Time::ZERO, now);

        clock.advance(1_000_000_000);
        let now = driver.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "now after advance",
            Time::from_secs(1),
            now
        );
        crate::test_complete!("timer_driver_now");
    }

    #[test]
    fn timer_driver_with_browser_clock_respects_catch_up_cap() {
        init_test("timer_driver_with_browser_clock_respects_catch_up_cap");
        let clock = Arc::new(BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::from_millis(50),
            jitter_floor: Duration::ZERO,
        }));
        let driver = TimerDriver::with_clock(clock.clone());
        let woken = Arc::new(AtomicBool::new(false));

        let _ = clock.observe_host_time(Duration::ZERO);
        driver.register(Time::from_millis(80), waker_that_sets(woken.clone()));

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let fired_1 = driver.process_timers();
        crate::assert_with_log!(
            fired_1 == 0,
            "first capped catch-up does not fire 80ms timer",
            0usize,
            fired_1
        );

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let fired_2 = driver.process_timers();
        crate::assert_with_log!(
            fired_2 == 1,
            "second catch-up slice fires timer",
            1usize,
            fired_2
        );
        crate::assert_with_log!(
            woken.load(Ordering::SeqCst),
            "timer waker called after bounded catch-up",
            true,
            woken.load(Ordering::SeqCst)
        );
        crate::test_complete!("timer_driver_with_browser_clock_respects_catch_up_cap");
    }

    // =========================================================================
    // TimerHandle Tests
    // =========================================================================

    #[test]
    fn timer_handle_id_and_generation() {
        init_test("timer_handle_id_and_generation");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        let h1 = driver.register(Time::from_secs(1), futures_waker());
        let h2 = driver.register(Time::from_secs(2), futures_waker());

        crate::assert_with_log!(h1.id() == 0, "h1 id", 0, h1.id());
        crate::assert_with_log!(h2.id() == 1, "h2 id", 1, h2.id());
        let gen1 = h1.generation();
        let gen2 = h2.generation();
        crate::assert_with_log!(
            gen1 != gen2,
            "generation differs",
            "not equal",
            (gen1, gen2)
        );
        crate::test_complete!("timer_handle_id_and_generation");
    }

    // =========================================================================
    // TimerDriverHandle Tests (bd-rpsc)
    // =========================================================================

    #[test]
    fn timer_driver_handle_with_virtual_clock() {
        init_test("timer_driver_handle_with_virtual_clock");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let now = handle.now();
        crate::assert_with_log!(now == Time::ZERO, "initial time", Time::ZERO, now);

        clock.advance(1_000_000_000);
        let now = handle.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "time after advance",
            Time::from_secs(1),
            now
        );
        crate::test_complete!("timer_driver_handle_with_virtual_clock");
    }

    #[test]
    fn timer_driver_handle_register_and_cancel() {
        init_test("timer_driver_handle_register_and_cancel");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let woken = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(woken.clone());
        let timer_handle = handle.register(Time::from_secs(5), waker);

        // Cancel before firing
        let cancelled = handle.cancel(&timer_handle);
        crate::assert_with_log!(cancelled, "timer cancelled", true, cancelled);

        // Advance past deadline and process - nothing should fire
        clock.set(Time::from_secs(10));
        let fired = handle.process_timers();
        crate::assert_with_log!(fired == 0, "no timers fire after cancel", 0usize, fired);
        let woken_val = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(!woken_val, "waker not called", false, woken_val);
        crate::test_complete!("timer_driver_handle_register_and_cancel");
    }

    #[test]
    fn timer_driver_handle_update_reschedules() {
        init_test("timer_driver_handle_update_reschedules");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let counter = Arc::new(AtomicU64::new(0));
        let waker = waker_that_increments(counter.clone());
        let timer_handle = handle.register(Time::from_secs(5), waker);

        // Update to fire at 2s instead
        let waker2 = waker_that_increments(counter.clone());
        let _new_handle = handle.update(&timer_handle, Time::from_secs(2), waker2);

        // Advance to 3s - should fire the updated timer
        clock.set(Time::from_secs(3));
        let fired = handle.process_timers();
        crate::assert_with_log!(fired == 1, "updated timer fires", 1usize, fired);
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter incremented", 1u64, count);

        // Advance to 10s - old deadline should not fire again
        clock.set(Time::from_secs(10));
        let fired = handle.process_timers();
        crate::assert_with_log!(fired == 0, "old timer cancelled", 0usize, fired);
        crate::test_complete!("timer_driver_handle_update_reschedules");
    }

    #[test]
    fn timer_driver_handle_next_deadline() {
        init_test("timer_driver_handle_next_deadline");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock);

        let no_deadline = handle.next_deadline();
        crate::assert_with_log!(
            no_deadline.is_none(),
            "no deadline when empty",
            true,
            no_deadline.is_none()
        );

        let _ = handle.register(Time::from_secs(10), futures_waker());
        let _ = handle.register(Time::from_secs(3), futures_waker());
        let _ = handle.register(Time::from_secs(7), futures_waker());

        let next = handle.next_deadline();
        crate::assert_with_log!(
            next == Some(Time::from_secs(3)),
            "earliest deadline returned",
            Some(Time::from_secs(3)),
            next
        );
        crate::test_complete!("timer_driver_handle_next_deadline");
    }

    #[test]
    fn timer_driver_handle_ptr_eq() {
        init_test("timer_driver_handle_ptr_eq");
        let clock = Arc::new(VirtualClock::new());
        let handle1 = TimerDriverHandle::with_virtual_clock(clock.clone());
        let handle2 = TimerDriverHandle::with_virtual_clock(clock);

        // Different driver instances, even with same clock
        let eq = handle1.ptr_eq(&handle2);
        crate::assert_with_log!(!eq, "different drivers not equal", false, eq);
        crate::test_complete!("timer_driver_handle_ptr_eq");
    }

    #[test]
    fn timer_driver_handle_with_browser_clock() {
        init_test("timer_driver_handle_with_browser_clock");
        let clock = Arc::new(BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::ZERO,
        }));
        let handle = TimerDriverHandle::with_browser_clock(clock.clone());

        let _ = clock.observe_host_time(Duration::from_millis(20));
        let _ = clock.observe_host_time(Duration::from_millis(35));
        let now = handle.now();
        crate::assert_with_log!(
            now == Time::from_millis(15),
            "driver handle reflects browser clock advancement",
            Time::from_millis(15),
            now
        );
        crate::test_complete!("timer_driver_handle_with_browser_clock");
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

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
    fn futures_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    /// A waker that sets an AtomicBool when woken.
    struct FlagWaker {
        flag: AtomicBool,
    }

    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    /// Creates a waker that sets an AtomicBool when woken.
    fn waker_that_sets(flag: Arc<AtomicBool>) -> Waker {
        // We create a new FlagWaker that shares the flag
        // by wrapping the Arc<AtomicBool> in another struct
        struct SharedFlagWaker {
            flag: Arc<AtomicBool>,
        }

        impl Wake for SharedFlagWaker {
            fn wake(self: Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }
        }

        Arc::new(SharedFlagWaker { flag }).into()
    }

    /// A waker that increments a counter when woken.
    struct CounterWaker {
        counter: Arc<AtomicU64>,
    }

    impl Wake for CounterWaker {
        fn wake(self: Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Creates a waker that increments an AtomicU64 when woken.
    fn waker_that_increments(counter: Arc<AtomicU64>) -> Waker {
        Arc::new(CounterWaker { counter }).into()
    }
}
